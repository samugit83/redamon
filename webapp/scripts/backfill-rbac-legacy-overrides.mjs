/**
 * Converts the legacy grants (`User.legacyGrants`, backfill-rbac-legacy-grants.mjs) the first
 * time the webapp boots with the permission engine on (step 3.15, HD-02, OQ-26).
 *
 * A grant whose latest review decision is Keep (`rbac.legacy_grant.keep`, written by the admin
 * review in src/lib/authz/updateReview.ts) becomes an override grant of its platform
 * permission (`kali_terminal` -> `platform:kali_terminal`, `shell_sessions` ->
 * `platform:shell_sessions`, `tunnels` -> `platform:tunnels`), with the reason "kept from
 * 7.7.x" and an end 90 days after the conversion, given by the admin who kept it. Every other
 * grant lapses: from the conversion on, the resolution (src/lib/authz/capabilities.ts) no longer
 * reads the column. The column itself is never written, so turning the switch off again finds
 * Phase 1's grants (the roll-back).
 *
 * Runs only when RBAC_PERMISSIONS_ENABLED is on, which reads off while RBAC_IDENTITY_ENABLED
 * is off (src/lib/authz/flags.ts; a test holds the two parses equal).
 *
 * Every boot with the switch on checks each held grant, so the marker never hides missing
 * data: a Keep becomes an override once, and is skipped when an override for that permission
 * already stands (written here, by the review card or by a person), when a person changed the
 * account's permissions after the Keep (`user.permissions_changed`: their change stands), or
 * when its 90 days are over. A downgrade's `db push` drops the override table but not the
 * AuditLog, so the next boot writes the overrides again, ending when the first ones did: the
 * 90 days run from the first conversion (its marker), or from a later Keep.
 *
 * Under the review's lock (decisions and the column) and then the permission writers' lock
 * (overrides), so two webapp copies booting together convert once and never cross an admin's
 * change. The marker (`system.rbac_legacy_overrides_backfill`, with the counts) is written in
 * the same transaction as the overrides: by the first conversion, even when nothing was kept
 * (the resolution reads it to stop counting the column), and by any later boot that wrote one.
 *
 * Runs from the webapp entrypoint AFTER `db push` and the legacy grants backfill, and from the
 * dev container's command. Never fatal: a failure is logged and the next boot tries again.
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'
import { identitySwitchOn } from './backfill-rbac-instance-settings.mjs'
import { LEGACY_GRANTS, LOCK_KEY as REVIEW_LOCK, REMOVE_ACTION } from './backfill-rbac-legacy-grants.mjs'

export { REVIEW_LOCK }
// src/lib/authz/permissionAdmin.ts PERMISSIONS_LOCK: every writer of an override takes it.
export const PERMISSIONS_LOCK = 'rbac.permissions'
export const MARKER_ACTION = 'system.rbac_legacy_overrides_backfill'
export const KEEP_ACTION = 'rbac.legacy_grant.keep'
// What src/lib/authz/userPermissionAdmin.ts records for a person's change of an account.
export const CHANGED_ACTION = 'user.permissions_changed'
export const KEPT_REASON = 'kept from 7.7.x'
export const KEEP_DAYS = 90 // PLACEHOLDER(OQ-26)
export const LEGACY_PERMISSION = Object.freeze({
  kali_terminal: 'platform:kali_terminal',
  shell_sessions: 'platform:shell_sessions',
  tunnels: 'platform:tunnels',
})

const DAY_MS = 86_400_000
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const key = (accountId, item) => `${accountId}\u0000${item}`

const switchValue = (raw) => ['true', '1', 'yes'].includes(String(raw ?? '').trim().toLowerCase())

/** RBAC_PERMISSIONS_ENABLED as src/lib/authz/flags.ts reads it: off while the identity switch is off. */
export function permissionsSwitchOn(env = process.env) {
  return identitySwitchOn(env) && switchValue(env.RBAC_PERMISSIONS_ENABLED)
}

/**
 * The latest review decision per account and grant (`rows` oldest first): {keep, at, by}.
 * A Remove after a Keep is no Keep.
 */
export function latestDecisions(rows) {
  const out = new Map()
  for (const r of rows) {
    const grant = isPlainObject(r.after) && typeof r.after.grant === 'string' ? r.after.grant : null
    if (!grant || !r.targetId) continue
    out.set(key(r.targetId, grant), { keep: r.action === KEEP_ACTION, at: r.createdAt, by: r.actorId ?? null })
  }
  return out
}

/**
 * What the conversion writes: the overrides and the counts. `members` {id, legacyGrants} are
 * the non-admin accounts holding a grant; `standing` the keys (account, permission) of the
 * overrides that exist; `changedAt` the latest person's change per account; `anchor` the first
 * conversion's time (null: this one).
 */
export function planLegacyOverrides({ members, decisions, standing, changedAt, anchor, now }) {
  const counts = { converted: 0, lapsed: 0, overridden: 0, superseded: 0, expired: 0 }
  const byGrant = Object.fromEntries(LEGACY_GRANTS.map((g) => [g, 0]))
  const overrides = []
  for (const member of members) {
    for (const grant of LEGACY_GRANTS) {
      if (!member.legacyGrants.includes(grant)) continue
      const permission = LEGACY_PERMISSION[grant]
      const decision = decisions.get(key(member.id, grant))
      if (!decision?.keep) { counts.lapsed++; continue }
      if (standing.has(key(member.id, permission))) { counts.overridden++; continue }
      const changed = changedAt.get(member.id)
      if (changed && changed > decision.at) { counts.superseded++; continue }
      const start = Math.max(decision.at.getTime(), (anchor ?? now).getTime())
      const expiresAt = new Date(start + KEEP_DAYS * DAY_MS)
      if (expiresAt <= now) { counts.expired++; continue }
      overrides.push({
        userId: member.id, permission, effect: 'grant', expiresAt, reason: KEPT_REASON,
        grantedById: decision.by ?? 'system',
      })
      counts.converted++
      byGrant[grant]++
    }
  }
  return { overrides, counts, byGrant }
}

/**
 * {ran: false} with the switch off (nothing read); else the counts and whether a marker was
 * written (`marker`).
 */
export async function backfillRbacLegacyOverrides(prisma, env = process.env, { now: clock = () => new Date() } = {}) {
  if (!permissionsSwitchOn(env)) return { ran: false }
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${REVIEW_LOCK}))`
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${PERMISSIONS_LOCK}))`
    const first = await tx.auditLog.findFirst({
      where: { action: MARKER_ACTION }, orderBy: [{ createdAt: 'asc' }, { id: 'asc' }], select: { createdAt: true },
    })
    const members = await tx.user.findMany({
      where: { role: { not: 'admin' }, legacyGrants: { hasSome: LEGACY_GRANTS } },
      select: { id: true, legacyGrants: true },
      orderBy: { id: 'asc' },
    })
    const ids = members.map((m) => m.id)
    const decisions = latestDecisions(ids.length === 0 ? [] : await tx.auditLog.findMany({
      where: { action: { in: [KEEP_ACTION, REMOVE_ACTION] }, targetType: 'user', targetId: { in: ids } },
      select: { action: true, targetId: true, actorId: true, after: true, createdAt: true },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    }))
    const standing = new Set(ids.length === 0 ? [] : (await tx.userPermissionOverride.findMany({
      where: { userId: { in: ids }, permission: { in: Object.values(LEGACY_PERMISSION) } },
      select: { userId: true, permission: true },
    })).map((o) => key(o.userId, o.permission)))
    const changedAt = new Map()
    if (ids.length > 0) {
      for (const r of await tx.auditLog.findMany({
        where: { action: CHANGED_ACTION, targetId: { in: ids } }, select: { targetId: true, createdAt: true },
      })) {
        const seen = changedAt.get(r.targetId)
        if (!seen || r.createdAt > seen) changedAt.set(r.targetId, r.createdAt)
      }
    }

    const now = clock()
    const { overrides, counts, byGrant } = planLegacyOverrides({
      members, decisions, standing, changedAt, anchor: first?.createdAt ?? null, now,
    })
    if (overrides.length > 0) await tx.userPermissionOverride.createMany({ data: overrides })
    const expiresAt = overrides.reduce((latest, o) => (latest && latest > o.expiresAt ? latest : o.expiresAt), null)
    const after = { ...counts, ...byGrant, expiresAt: expiresAt ? expiresAt.toISOString() : null }
    const marker = !first || overrides.length > 0
    if (marker) {
      // Stamped with the time the ends were computed from: a later boot's 90 days start there.
      await tx.auditLog.create({ data: { action: MARKER_ACTION, targetType: 'system', source: 'system', after, createdAt: now } })
    }
    return { ran: true, marker, ...after }
  }, { timeout: 120_000, maxWait: 30_000 })
}

export async function run(prisma, env = process.env, options = {}) {
  try {
    const r = await backfillRbacLegacyOverrides(prisma, env, options)
    if (r.ran && r.marker) {
      console.log(`[rbac] legacy grants converted: ${r.converted} kept grant(s) became override(s)${r.expiresAt ? ` ending ${r.expiresAt}` : ''}, ${r.lapsed} lapsed (${r.overridden} already overridden, ${r.superseded} changed since, ${r.expired} past their ${KEEP_DAYS} days).`)
    }
  } catch (err) {
    // A database error quotes no values here: the queries carry only ids, actions and the lock keys.
    console.error('[rbac] could not convert the legacy grants (retried next boot):', String(err?.message || err).replace(/\s+/g, ' ').trim())
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const prisma = new PrismaClient()
  run(prisma).finally(() => prisma.$disconnect().catch(() => {}))
}
