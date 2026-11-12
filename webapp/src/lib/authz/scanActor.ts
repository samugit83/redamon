/**
 * Deferred work of an account that is not active does not fire (step 2.3, DV-39). A schedule
 * and a queued job start their scan headless, on the keys and settings of the account that
 * created them and of the project's owner; once either account is disabled (or gone), the
 * scan must not start on its behalf. The schedule run and the queue dispatch ask here before
 * they start anything.
 *
 * With the identity switch off nothing is read and nothing is refused (Phase 1 behaviour).
 */
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'

export interface InactiveScanAccount {
  userId: string
  /** `actor`: the account that created the schedule or queued the job; `owner`: the project's owner. */
  as: 'actor' | 'owner'
  /** The account's status, or `deleted` when no such account exists. */
  status: string
}

export interface ScanAccounts {
  actorUserId: string
  /** The project's owner, when the caller already read the project. */
  ownerUserId?: string | null
  /** Read the owner from this project when `ownerUserId` is not given. */
  projectId?: string
}

/** The first of the scan's accounts that is not active, or null (always null with the switch off). */
export async function inactiveScanAccount(accounts: ScanAccounts): Promise<InactiveScanAccount | null> {
  if (!rbacFlags().identity) return null
  let owner = accounts.ownerUserId ?? null
  if (accounts.ownerUserId === undefined && accounts.projectId) {
    const project = await prisma.project.findUnique({ where: { id: accounts.projectId }, select: { userId: true } })
    // A project that is gone is the start path's own refusal; only its owner is judged here.
    owner = project?.userId ?? null
  }
  const ids = [...new Set([accounts.actorUserId, owner].filter((v): v is string => !!v))]
  const rows = await prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true, status: true } })
  const status = new Map(rows.map((r) => [r.id, r.status]))
  const checks: Array<[string | null, InactiveScanAccount['as']]> = [[accounts.actorUserId, 'actor'], [owner, 'owner']]
  for (const [userId, as] of checks) {
    if (!userId) continue
    const s = status.get(userId) ?? 'deleted'
    if (s !== 'active') return { userId, as, status: s }
  }
  return null
}

/** The reason a skipped schedule or a cancelled job records, in words for the run history. */
export function inactiveScanReason(inactive: InactiveScanAccount, done: 'scheduled' | 'queued'): string {
  const whose = inactive.as === 'actor' ? `the account that ${done} it` : "the project owner's account"
  return `${whose} is ${inactive.status}`
}
