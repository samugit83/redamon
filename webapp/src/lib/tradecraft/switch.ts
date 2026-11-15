/**
 * The per-account Tradecraft 2.0 switch (TD-1): `TradecraftUserSettings.v2Enabled`, off
 * by default and off when the account has no row. The only reader and writer of it, so
 * the cut-over (T9.3) removes one module. Not an RBAC switch: it is a person's own
 * choice for their own library, kept in the database because no environment variable
 * may be added (master plan §2).
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { actorFields, type AuditActor } from '@/lib/auditActor'
import { now } from '@/lib/authz/clock'

export async function tradecraftV2Enabled(userId: string): Promise<boolean> {
  const row = await prisma.tradecraftUserSettings.findUnique({ where: { userId }, select: { v2Enabled: true } })
  return row?.v2Enabled === true
}

/**
 * Serializes the writers of one account's `TradecraftUserSettings` row until the transaction
 * ends. A row lock cannot do it: the row may not exist yet. Every writer of the row takes it
 * first, so a read inside the transaction sees the last committed value.
 */
export async function lockTradecraftUserSettings(tx: Prisma.TransactionClient, userId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`tradecraft_user_settings:${userId}`}))`
}

/**
 * Turns 2.0 on or off for `userId`, with its audit row in the same transaction: a failed
 * audit insert rolls the change back. Setting the value it already has writes nothing.
 * `actor` is the request's person (`auditActor()`), the account acted as on whose behalf.
 */
export async function setTradecraftV2(actor: AuditActor, userId: string, enabled: boolean): Promise<void> {
  await auditedTransaction(prisma, async (tx) => {
    // Without it two requests at once (a double click) both read the old value and both
    // write an audit row, the second with a wrong `before`.
    await lockTradecraftUserSettings(tx, userId)
    const before = await tx.tradecraftUserSettings.findUnique({ where: { userId }, select: { v2Enabled: true } })
    const was = before?.v2Enabled === true
    if (was === enabled) return
    const v2EnabledAt = enabled ? now() : null
    await tx.tradecraftUserSettings.upsert({
      where: { userId },
      create: { userId, v2Enabled: enabled, v2EnabledAt },
      update: { v2Enabled: enabled, v2EnabledAt },
    })
    await writeAuditTx(tx, {
      ...actorFields(actor),
      action: 'tradecraft.v2_switched',
      permission: 'self:tradecraft',
      targetType: 'user',
      targetId: userId,
      before: { v2Enabled: was },
      after: { v2Enabled: enabled },
    })
  })
}
