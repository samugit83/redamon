/**
 * One-time notices to an account (step 2.10, ID-19; feature document §7.1): a credentials reset
 * is takeover-equivalent, whoever issued it can use it first, so the person is told. The reset
 * writes a notice into the account's `pendingNotices`; the next sign-in hands the pending ones
 * to the person once and marks them shown. The account keeps them, the newest NOTICE_LIMIT, for
 * its activity list (step 2.11). A change of the sign-in email is told the same way (step 2.11,
 * ID-30): whoever changes it can then reset the password through it.
 *
 * The first sign-in after a reset is the one whose account last signed in before the latest
 * reset notice; only that sign-in records its address and browser (DV-11).
 */
import { randomUUID } from 'node:crypto'
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import { now } from './clock'

export const NOTICE_LIMIT = 20

export type ResetMode = 'link' | 'temporary'

export interface CredentialsResetNotice {
  id: string
  type: 'credentials_reset'
  /** When the reset happened (ISO). */
  at: string
  /** The person who reset it (the real signed-in admin, never an account it acted as). */
  by: { id: string; name: string; email: string }
  reason: string | null
  mode: ResetMode
  /** When a sign-in handed it to the person; absent while pending. */
  shownAt?: string
}

export interface EmailChangedNotice {
  id: string
  type: 'email_changed'
  at: string
  /** Who changed it: the account itself (`self`), or the real signed-in admin. */
  by: { id: string; name: string; email: string }
  from: string
  to: string
  self: boolean
  shownAt?: string
}

export type AccountNotice = CredentialsResetNotice | EmailChangedNotice

/** What the person is shown: the notice without the admin's account id. */
export type NoticeView =
  | {
    id: string
    type: 'credentials_reset'
    at: string
    by: { name: string; email: string }
    reason: string | null
    mode: ResetMode
  }
  | {
    id: string
    type: 'email_changed'
    at: string
    by: { name: string; email: string }
    from: string
    to: string
    self: boolean
  }

const text = (v: unknown): v is string => typeof v === 'string'

function isNotice(v: unknown): v is AccountNotice {
  if (!v || typeof v !== 'object') return false
  const n = v as Record<string, unknown>
  const by = n.by as Record<string, unknown> | null | undefined
  const common = text(n.id) && text(n.at) && !Number.isNaN(Date.parse(n.at))
    && !!by && typeof by === 'object' && text(by.id) && text(by.name) && text(by.email)
    && (n.shownAt === undefined || text(n.shownAt))
  if (!common) return false
  if (n.type === 'credentials_reset') {
    return (n.mode === 'link' || n.mode === 'temporary') && (n.reason === null || text(n.reason))
  }
  return n.type === 'email_changed' && text(n.from) && text(n.to) && typeof n.self === 'boolean'
}

/** The notices a stored value holds; anything else (a row from before this step, a bad entry) is none. */
export function readNotices(value: unknown): AccountNotice[] {
  return Array.isArray(value) ? value.filter(isNotice) : []
}

export function credentialsResetNotice(
  { by, at, reason, mode }: { by: CredentialsResetNotice['by']; at: Date; reason: string | null; mode: ResetMode },
): CredentialsResetNotice {
  return { id: randomUUID(), type: 'credentials_reset', at: at.toISOString(), by, reason, mode }
}

export function emailChangedNotice(
  { by, at, from, to, self }: { by: EmailChangedNotice['by']; at: Date; from: string; to: string; self: boolean },
): EmailChangedNotice {
  return { id: randomUUID(), type: 'email_changed', at: at.toISOString(), by, from, to, self }
}

/** `stored` with `notice` appended, keeping the newest NOTICE_LIMIT. */
export function withNotice(stored: unknown, notice: AccountNotice): AccountNotice[] {
  return [...readNotices(stored), notice].slice(-NOTICE_LIMIT)
}

export function pendingNotices(stored: unknown): AccountNotice[] {
  return readNotices(stored).filter((n) => !n.shownAt)
}

/** The latest credentials reset the account was told about, or null. */
export function latestReset(stored: unknown): CredentialsResetNotice | null {
  let latest: CredentialsResetNotice | null = null
  for (const n of readNotices(stored)) {
    if (n.type === 'credentials_reset' && (!latest || Date.parse(n.at) > Date.parse(latest.at))) latest = n
  }
  return latest
}

/** Whether a sign-in by an account that last signed in at `lastLoginAt` is its first since a reset. */
export function firstSignInAfterReset(lastLoginAt: Date | null, stored: unknown): boolean {
  const reset = latestReset(stored)
  if (!reset) return false
  return !lastLoginAt || lastLoginAt.getTime() < Date.parse(reset.at)
}

/**
 * `auth.login.after_reset`'s payload: the address and browser of the first sign-in after a
 * reset, the only sign-in whose address and browser this feature records (DV-11).
 */
export function afterResetEntry(
  userId: string,
  meta: { ip: string | null; ipTrusted: boolean; userAgent: string | null },
  stored: unknown,
) {
  const reset = latestReset(stored)
  return {
    actorId: userId,
    action: 'auth.login.after_reset',
    targetType: 'user',
    targetId: userId,
    after: {
      ip: meta.ip,
      ipTrusted: meta.ipTrusted,
      userAgent: meta.userAgent,
      ...(reset ? { resetAt: reset.at, resetMode: reset.mode } : {}),
    },
  }
}

export function noticeView(n: AccountNotice): NoticeView {
  const by = { name: n.by.name, email: n.by.email }
  if (n.type === 'email_changed') return { id: n.id, type: n.type, at: n.at, by, from: n.from, to: n.to, self: n.self }
  return { id: n.id, type: n.type, at: n.at, by, reason: n.reason, mode: n.mode }
}

/** `stored` with every pending notice marked shown now. */
export function markShown(stored: unknown): AccountNotice[] {
  const at = now().toISOString()
  return readNotices(stored).map((n) => (n.shownAt ? n : { ...n, shownAt: at }))
}

/**
 * At a sign-in: the pending notices, for the person to see once, and the stored list marked
 * shown. Raw, so the account's `updated_at` does not move, and conditional on the list read at
 * the sign-in, so a notice that arrived meanwhile is never overwritten (it stays pending). Never
 * fails the sign-in: a failed write is logged with its code and the notices are shown anyway.
 */
export async function handOverNotices(userId: string, stored: unknown): Promise<NoticeView[]> {
  const pending = pendingNotices(stored)
  if (pending.length === 0) return []
  try {
    await prisma.$executeRaw`
      UPDATE users SET pending_notices = ${JSON.stringify(markShown(stored))}::jsonb WHERE id = ${userId} AND pending_notices = ${JSON.stringify(stored)}::jsonb`
  } catch (err) {
    console.error(`[rbac] notice write failed user=${userId} code=${safeErrorCode(err)}`)
  }
  return pending.map(noticeView)
}
