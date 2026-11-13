/**
 * Reads made while acting as an account (IM-07, D-22; feature document §4.7): an admin acting as a
 * collaborator reads the collaborator's shared project read-only (projectAccess caps the share at
 * `read` for an acting session), and the owner's activity feed names the admin for it.
 *
 * - The audit: one `project.read_acting` row per admin, account acted as, project and UTC day (the
 *   unit of the oversight row, DV-24), written by the route guard (guards.ts) for every request it
 *   allowed through that account's share while acting. `actorId` is the admin, `onBehalfOfUserId`
 *   the account acted as (AU-01), so the feed reads "Opened the project, by <admin> acting as
 *   <collaborator>". Written as oversight.ts writes its row: one transaction holding
 *   `pg_advisory_xact_lock(hashtext('act_as_read:<admin>:<account>:<project>:<day>'))` first looks for
 *   the day's row, so two webapp copies cannot both write it, and each process remembers the rows it
 *   wrote or found, so the next read costs nothing. A failed write throws: the guard refuses the read
 *   (no row, no read).
 * - Nothing for any other read: the owner's own, a collaborator's own, an admin acting as the owner
 *   (the account acted as reads its own project), oversight (its own row, never while acting) and
 *   break-glass (refused while acting). With sharing off no share is read, so no row either (DV-30).
 */
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { now } from './clock'
import { oversightDay } from './oversight'
import type { ProjectAccess } from './projectAccess'

export const ACT_AS_READ_ACTION = 'project.read_acting'
/** What let the admin read: acting as the account (the share is that account's). */
const ACT_AS_PERMISSION = 'users:impersonate'
const DAY_MS = 86_400_000

export function actAsReadLockKey(actorId: string, onBehalfOfUserId: string, projectId: string, day: string): string {
  return `act_as_read:${actorId}:${onBehalfOfUserId}:${projectId}:${day}`
}

let memoDay = ''
const recorded = new Set<string>()

export function clearActAsReadMemoForTests(): void {
  memoDay = ''
  recorded.clear()
}

/** Who asked, as the guards read them: the admin signed in and the account acted as. */
export interface ActAsReadIdentity {
  principal: { id: string; email?: string | null }
  actingAs?: { id: string } | null
}

async function recordActAsRead(admin: ActAsReadIdentity['principal'], onBehalfOfUserId: string, projectId: string, read: string): Promise<void> {
  const day = oversightDay(now())
  if (day !== memoDay) {
    recorded.clear()
    memoDay = day
  }
  const key = actAsReadLockKey(admin.id, onBehalfOfUserId, projectId, day)
  if (recorded.has(key)) return
  const start = new Date(`${day}T00:00:00.000Z`)
  const end = new Date(start.getTime() + DAY_MS)
  await auditedTransaction(prisma, async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key}))`
    const existing = await tx.auditLog.findFirst({
      where: { action: ACT_AS_READ_ACTION, actorId: admin.id, onBehalfOfUserId, projectId, createdAt: { gte: start, lt: end } },
      select: { id: true },
    })
    if (existing) return
    await writeAuditTx(tx, {
      actorId: admin.id,
      ...(admin.email ? { actorEmail: admin.email } : {}),
      onBehalfOfUserId,
      projectId,
      permission: ACT_AS_PERMISSION,
      action: ACT_AS_READ_ACTION,
      targetType: 'project',
      targetId: projectId,
      after: { day, read },
      source: 'api',
    })
  })
  recorded.add(key)
}

/**
 * The audit of a read that `access` allowed: the day's row when the person acts as an account and the
 * access is that account's share; nothing for any other access. `read` is the permission the request
 * used, kept in the row's `after`. Throws when the row can be neither found nor written.
 */
export async function auditActAsRead(identity: ActAsReadIdentity, access: ProjectAccess | null | undefined, read: string): Promise<void> {
  if (access?.via !== 'share' || !identity.actingAs) return
  await recordActAsRead(identity.principal, identity.actingAs.id, access.project.id, read)
}
