/**
 * The last admin with a password (HD-09). A passwordless account cannot sign in, so
 * an instance whose only admins are passwordless has nobody left to administer it.
 *
 * Each demotion or deletion of an admin alone leaves the actor behind, but two at
 * once (two admins demoting each other) can remove both. So the check and the write
 * run in one transaction that first takes `pg_advisory_xact_lock(hashtext('rbac.admin_set'))`:
 * the second transaction waits, then reads the first one's committed result. The lock
 * is per database, so it also holds across several webapp copies.
 */
import prisma from '@/lib/prisma'
import type { Prisma } from '@prisma/client'

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

/**
 * Runs `write` unless it would remove the last admin with a password: `targetId` is
 * read under the lock, and when it is such an admin, another one must remain.
 * `write` gets that read (never the hash). `{ok: false}` means nothing was written.
 */
export async function withLastAdminGuard<T>(
  targetId: string,
  write: (tx: Prisma.TransactionClient, target: GuardedAccount | null) => Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false }> {
  return prisma.$transaction(async (tx) => {
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
