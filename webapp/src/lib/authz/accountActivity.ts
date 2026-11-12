/**
 * "My activity" (step 2.11, UI-09; feature document §7.1 "the person is told at their next
 * sign-in and in their feed"): what happened to an account that its owner should be able to see
 * at any time. The account's notices (step 2.10's list: pending and already shown), the audit rows
 * about it from a safe list (credentials resets and the first sign-in after one, sign-in email
 * changes, Root changes), and admins acting as it (the act-as log).
 *
 * Each row carries only the fields named here, and who did it by name and email; never an account
 * id, a token, a hash or a password (the rows themselves never hold the last three). The page is a
 * read of the newest ACTIVITY_PAGE rows of each source.
 *
 * With RBAC_PERMISSIONS_ENABLED on (step 3.14): an act-as row carries its reason, chosen duration and
 * how it ended; an impersonation whose time ran out is ended (`expired`) before the list is read; and
 * with Root's `impersonationNotifyTarget` off the account is not shown admins acting as it.
 */
import prisma from '@/lib/prisma'
import { noticeView, readNotices, type NoticeView } from './accountNotices'
import { rbacFlags } from './flags'
import { impersonationPolicy, settleExpiredActAsQuietly } from './actAs'

export const ACTIVITY_PAGE = 50

/** Audit actions about an account that its owner sees, with the fields of each it may read. */
const SAFE_FIELDS: Record<string, (before: Record<string, unknown>, after: Record<string, unknown>) => Record<string, unknown>> = {
  'user.credentials_reset': (_b, a) => ({ mode: a.mode, reason: a.reason ?? null, mustChangePassword: a.mustChangePassword }),
  // The account's own first sign-in after a reset: the address and browser it came from (DV-11).
  'auth.login.after_reset': (_b, a) => ({ ip: a.ip ?? null, userAgent: a.userAgent ?? null }),
  'user.email_changed': (b, a) => ({ from: b.email ?? null, to: a.email ?? null }),
  'root.transfer_offered': (_b, a) => ({ expiresAt: a.expiresAt ?? null }),
  'root.transfer': () => ({}),
  'root.transfer_cancelled': () => ({}),
  'root.transfer_declined': () => ({}),
  'root.set_by_host': () => ({}),
  'root.confirmed_by_host': () => ({}),
  'system.rbac_root_assigned': (_b, a) => ({ rule: a.rule ?? null }),
}

export const SAFE_ACTIVITY_ACTIONS: readonly string[] = Object.freeze(Object.keys(SAFE_FIELDS))

export interface ActivityEvent {
  id: string
  at: string
  /** An audit action of the safe list, or `act_as.start` / `act_as.end`. */
  action: string
  /** Who did it; null for the host, the system or an account gone without a recorded address. */
  by: { name: string; email: string } | null
  details: Record<string, unknown>
}

/** The act-as notices are shown once at a sign-in; the act-as events below are their lasting line. */
export type ActivityNotice = Exclude<NoticeView, { type: 'acted_as' }> & { shownAt: string | null }

const asObject = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {})

/** The account's notices and the events about it, each list newest first. */
export async function accountActivity(userId: string): Promise<{ notices: ActivityNotice[]; events: ActivityEvent[] }> {
  const account = await prisma.user.findUnique({ where: { id: userId }, select: { pendingNotices: true } })
  const enforced = rbacFlags().permissions
  const showActAs = !enforced || (await impersonationPolicy()).notifyTarget
  if (enforced && showActAs) await settleExpiredActAsQuietly({ targetUserId: userId })
  const [audit, actAs] = await Promise.all([
    prisma.auditLog.findMany({
      where: { targetType: 'user', targetId: userId, action: { in: [...SAFE_ACTIVITY_ACTIONS] } },
      orderBy: { createdAt: 'desc' },
      take: ACTIVITY_PAGE,
      select: { id: true, action: true, createdAt: true, actorId: true, actorEmail: true, before: true, after: true },
    }),
    showActAs
      ? prisma.actAsAudit.findMany({
        where: { targetUserId: userId },
        orderBy: { createdAt: 'desc' },
        take: ACTIVITY_PAGE,
        select: { id: true, adminId: true, event: true, createdAt: true, reason: true, durationMinutes: true, endedBy: true },
      })
      : Promise.resolve([]),
  ])

  const people = new Set<string>()
  for (const r of audit) if (r.actorId) people.add(r.actorId)
  for (const r of actAs) people.add(r.adminId)
  const found = people.size
    ? await prisma.user.findMany({ where: { id: { in: [...people] } }, select: { id: true, name: true, email: true } })
    : []
  const byId = new Map(found.map((u) => [u.id, u]))
  const who = (id: string | null, recordedEmail?: string | null): ActivityEvent['by'] => {
    const person = id ? byId.get(id) : undefined
    const email = recordedEmail || person?.email
    return email ? { name: person?.name ?? '', email } : null
  }

  const events: ActivityEvent[] = []
  for (const r of audit) {
    const fields = SAFE_FIELDS[r.action]
    if (!fields) continue
    events.push({
      id: r.id,
      at: r.createdAt.toISOString(),
      action: r.action,
      by: who(r.actorId, r.actorEmail),
      details: fields(asObject(r.before), asObject(r.after)),
    })
  }
  for (const r of actAs) {
    // Only what the row holds: a row from before step 3.14 shows no details, as it always did.
    const details: Record<string, unknown> = {}
    if (r.reason) details.reason = r.reason
    if (r.durationMinutes) details.durationMinutes = r.durationMinutes
    if (r.endedBy) details.endedBy = r.endedBy
    events.push({ id: r.id, at: r.createdAt.toISOString(), action: `act_as.${r.event}`, by: who(r.adminId), details })
  }
  events.sort((a, b) => Date.parse(b.at) - Date.parse(a.at))

  const notices = readNotices(account?.pendingNotices)
    .flatMap((n) => {
      const view = noticeView(n)
      return view.type === 'acted_as' ? [] : [{ ...view, shownAt: n.shownAt ?? null }]
    })
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at))
  return { notices, events: events.slice(0, ACTIVITY_PAGE) }
}
