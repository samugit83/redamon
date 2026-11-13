/**
 * Reading the instance audit log for the admin console (step 6.2; the audit viewer of step 6.6
 * reads it with its filters). Only the row's who, what and when are read: `before` and `after` can
 * hold personal data, so a list never carries them (master plan §9.8).
 */
import prisma from '@/lib/prisma'

export interface AuditRowView {
  id: string
  action: string
  createdAt: string
  actorId: string | null
  /** The actor's address when the row was written, so a deleted account is still named. */
  actorEmail: string | null
  onBehalfOfUserId: string | null
  targetType: string
  targetId: string | null
  projectId: string | null
  permission: string | null
  source: string
}

const ROW_SELECT = {
  id: true, action: true, createdAt: true, actorId: true, actorEmail: true, onBehalfOfUserId: true,
  targetType: true, targetId: true, projectId: true, permission: true, source: true,
} as const

/**
 * The latest rows where the account is the actor or the target (`targetType: 'user'`), newest first:
 * each side has its index (`actorId, createdAt` and `targetType, targetId, createdAt`). Rows written
 * by someone acting as the account carry it in `onBehalfOfUserId`, which has no index, so they are
 * not read here; the audit viewer finds them.
 */
export async function recentAuditAbout(userId: string, limit: number): Promise<AuditRowView[]> {
  const rows = await prisma.auditLog.findMany({
    where: { OR: [{ actorId: userId }, { targetType: 'user', targetId: userId }] },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: limit,
    select: ROW_SELECT,
  })
  return rows.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() }))
}
