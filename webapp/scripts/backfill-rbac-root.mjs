/**
 * Recognises the instance's Root at boot (step 2.5, ID-09, master plan §14.4 step 1).
 *
 * Root is the one account no other account can demote, disable, delete, reset, sign out or
 * act as (with RBAC_IDENTITY_ENABLED on). An install made before Root existed has none, so
 * the first boot of this release picks one, the way the host would:
 *   - an existing admin is already Root (the instance settings row names it): nothing;
 *   - else the admins with a password (a passwordless one can never sign in): the only one,
 *     or the oldest of several (createdAt, then id), the order check-root.mjs lists them in;
 *   - none: no Root yet. create-admin.mjs makes the next admin Root.
 * The choice is "automatic" and unconfirmed: it has Root's protections but not the
 * Root-only powers until the host confirms it (`./redamon.sh update`, `set-root`).
 *
 * A Root id that names no account (deleted while the switch was off), or an account that is
 * no longer an admin (demoted then), is no Root: the readers (src/lib/authz/root.ts) treat it
 * so, and the next boot chooses again, recording the stale id.
 *
 * Two webapp copies booting together choose one Root: the choice runs under
 * `pg_advisory_xact_lock(hashtext('rbac-root'))`, the lock the host commands take to claim or
 * move Root (create-admin.mjs, set-root.mjs), and the write is conditional on the Root it read.
 * The `system.rbac_root_assigned` row commits with it. The skip needs no marker: it reads the
 * data itself, so a downgrade whose `db push` dropped the table (the AuditLog row survives) is
 * followed by a new choice.
 *
 * Runs whatever the identity switch (the Root is ready the day it goes on), from the webapp
 * entrypoint AFTER `db push` and the instance settings backfill, and from the dev container's
 * command. Never fatal: a failure, or no instance settings row yet, is logged and the next
 * boot tries again.
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

export const LOCK_KEY = 'rbac-root'
export const ASSIGNED_ACTION = 'system.rbac_root_assigned'
export const SINGLETON_ID = 'instance'
export const CANDIDATE_WHERE = { role: 'admin', password: { not: '' } }
export const CANDIDATE_ORDER = [{ createdAt: 'asc' }, { id: 'asc' }]

/** The Root among the candidates (oldest first), or null when there is none. */
export function chooseRoot(candidates) {
  if (candidates.length === 0) return null
  return {
    userId: candidates[0].id,
    rule: candidates.length === 1 ? 'only_admin' : 'oldest_admin',
    candidateCount: candidates.length,
  }
}

/**
 * {assigned: true, userId, rule, candidateCount} when it chose a Root; else
 * {assigned: false, rootUserId} (the Root in place, or null when there is none).
 */
export async function backfillRbacRoot(prisma) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`
    const row = await tx.instanceSettings.findUnique({ where: { id: SINGLETON_ID }, select: { rootUserId: true } })
    const recorded = row?.rootUserId ?? null
    if (recorded) {
      const root = await tx.user.findUnique({ where: { id: recorded }, select: { role: true } })
      if (root?.role === 'admin') return { assigned: false, rootUserId: recorded }
    }

    const candidates = await tx.user.findMany({ where: CANDIDATE_WHERE, orderBy: CANDIDATE_ORDER, select: { id: true } })
    const choice = chooseRoot(candidates)
    if (!choice) return { assigned: false, rootUserId: null, candidateCount: 0 }

    // Only the instance settings backfill creates the row, from the user rows: one of schema
    // defaults made here would win over them with the switch on (the readers fall back to the
    // user rows only while it is absent), dropping the tunnel credentials and storing capture
    // bodies. Its failure this boot leaves no row: wait for the next boot.
    if (!row) return { assigned: false, rootUserId: null, candidateCount: choice.candidateCount, noRow: true }
    // Conditional on the Root read above: a writer that does not take the lock (a Root
    // transfer) and moved it meanwhile wins, and nothing is recorded here.
    const { count } = await tx.instanceSettings.updateMany({
      where: { id: SINGLETON_ID, rootUserId: recorded },
      data: {
        rootUserId: choice.userId, rootConfirmedAt: null, rootAssignedBy: 'automatic',
        // An offer the previous Root made cannot outlive it.
        pendingRootTransferTo: null, pendingRootTransferExpires: null,
      },
    })
    if (count !== 1) return { assigned: false, rootUserId: null, candidateCount: choice.candidateCount, raced: true }

    await tx.auditLog.create({
      data: {
        action: ASSIGNED_ACTION, targetType: 'user', targetId: choice.userId, source: 'system',
        after: { ...choice, ...(recorded ? { previousRootUserId: recorded } : {}) },
      },
    })
    return { assigned: true, ...choice }
  }, { timeout: 60_000, maxWait: 30_000 })
}

export async function run(prisma) {
  try {
    const r = await backfillRbacRoot(prisma)
    if (r.assigned) {
      const why = r.rule === 'only_admin' ? 'the only admin with a password' : `the oldest of ${r.candidateCount} admins with a password`
      console.log(`[rbac] Root chosen automatically: user ${r.userId}, ${why}; unconfirmed until the host confirms it (./redamon.sh update or ./redamon.sh set-root <email>).`)
    } else if (r.noRow) {
      console.error('[rbac] could not recognise the Root (retried next boot):', 'the instance settings row is missing (its backfill has not filled it yet)')
    } else if (r.rootUserId === null && !r.raced) {
      console.log('[rbac] this instance has no Root yet: no admin has a password (./redamon.sh create-admin makes one, and it becomes Root).')
    }
  } catch (err) {
    // A database error quotes no values here: the queries carry only ids and the lock key.
    console.error('[rbac] could not recognise the Root (retried next boot):', String(err?.message || err).replace(/\s+/g, ' ').trim())
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const prisma = new PrismaClient()
  run(prisma).finally(() => prisma.$disconnect().catch(() => {}))
}
