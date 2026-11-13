/**
 * The last admin with a password (HD-09). A passwordless account cannot sign in, so
 * an instance whose only admins are passwordless has nobody left to administer it.
 *
 * Each demotion or deletion of an admin alone leaves the actor behind, but two at
 * once (two admins demoting each other) can remove both. So the check and the write
 * run in one transaction that first takes `pg_advisory_xact_lock(hashtext('rbac.admin_set'))`:
 * the second transaction waits, then reads the first one's committed result. The lock
 * is per database, so it also holds across several webapp copies.
 *
 * With the identity switch on, a caller that could leave the Root's row naming an account that
 * is no longer an active admin (a demotion, a deletion, a disable) passes `root`: the
 * transaction first takes the Root lock (root.ts ROOT_LOCK, always before this one, so the two
 * never wait on each other in opposite orders) and reads the Root again, as committed now. The
 * route's own check ran before the transaction, and a boot, a host set-root or a transfer may
 * have moved the Root since.
 */
import prisma from '@/lib/prisma'
import { auditedTransaction } from '@/lib/auditForward'
import type { Prisma } from '@prisma/client'
import { lockedInstanceRoot } from './root'

export const ADMIN_SET_LOCK = 'rbac.admin_set'

export const LAST_ADMIN_REFUSAL = {
  error: 'This is the last admin with a password: promote another account first.',
  code: 'last_admin',
} as const

/** The target as read under the lock, before the write: what an audit row's `before` shows. */
export interface GuardedAccount {
  name: string
  email: string
  role: string
}

export interface RootRecheck {
  /** The account acting. */
  actorId: string
  /** The write is a Root power: the actor must still be the confirmed Root. */
  needsRoot?: boolean
}

/** Why the Root re-check refused: the target is Root now, or the actor no longer holds Root's power. */
export type RootGuardRefusal = 'root_protected' | 'root_only'

/**
 * Runs `write` unless it would remove the last admin with a password: `targetId` is
 * read under the lock, and when it is such an admin, another one must remain.
 * `write` gets that read (never the hash). `{ok: false}` means nothing was written;
 * `refused` says the Root re-check (`root`) refused it rather than the last-admin rule.
 */
export async function withLastAdminGuard<T>(
  targetId: string,
  write: (tx: Prisma.TransactionClient, target: GuardedAccount | null) => Promise<T>,
  { root }: { root?: RootRecheck } = {},
): Promise<{ ok: true; value: T } | { ok: false; refused?: RootGuardRefusal }> {
  return auditedTransaction(prisma, async (tx) => {
    if (root) {
      const current = await lockedInstanceRoot(tx)
      if (current && current.userId === targetId) return { ok: false as const, refused: 'root_protected' as const }
      if (root.needsRoot && !(current && current.userId === root.actorId && current.confirmed)) {
        return { ok: false as const, refused: 'root_only' as const }
      }
    }
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${ADMIN_SET_LOCK}))`
    const target = await tx.user.findUnique({
      where: { id: targetId },
      select: { name: true, email: true, role: true, password: true },
    })
    if (target && target.role === 'admin' && target.password !== '') {
      const others = await tx.user.count({
        where: { role: 'admin', id: { not: targetId }, password: { not: '' } },
      })
      if (others === 0) return { ok: false as const }
    }
    const account = target && { name: target.name, email: target.email, role: target.role }
    return { ok: true as const, value: await write(tx, account) }
  })
}
