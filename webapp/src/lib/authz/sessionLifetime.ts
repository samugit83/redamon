/**
 * Session lifetimes (step 2.11, ID-24; feature document §7.1 "privileged sessions are shorter
 * ... and an idle timeout, both set by Root"). With the identity switch on, a login token lives
 * the instance's `memberSessionTtlHours`, or `adminSessionTtlHours` for Root and admins (Root is
 * an admin by role), and an admin's carries the idle limit `adminIdleMinutes`, which the
 * middleware enforces. The cookie lives exactly as long as its token. Off: Phase 1's 7-day login
 * and 12 h act-as, and nothing is read.
 *
 * Read at each sign-in, act-as and cookie re-issue, so a value Root changes applies to the next
 * one; a token already issued keeps the lifetime it was signed with.
 */
import prisma from '@/lib/prisma'
import { createToken } from '@/lib/auth'
import { safeErrorCode } from '@/lib/routeErrors'
import type { ClientMeta } from '@/lib/requestMeta'
import { rbacFlags } from './flags'
import { INSTANCE_SETTINGS_ROW } from './root'
import { now } from './clock'
import { deviceSessionsInForce, keepDeviceSession, openDeviceSession } from './deviceSessions'

const HOUR = 60 * 60

export const PHASE1_LOGIN_SECONDS = 7 * 24 * HOUR
export const PHASE1_ACT_AS_SECONDS = 12 * HOUR

export interface SessionLifetimes {
  memberSessionTtlHours: number
  adminSessionTtlHours: number
  adminIdleMinutes: number
}

/** The schema defaults, PLACEHOLDER(OQ-38): member 168 h (today's 7 days), admin 12 h, idle 60 min. */
export const LIFETIME_DEFAULTS: Readonly<SessionLifetimes> = Object.freeze({
  memberSessionTtlHours: 168,
  adminSessionTtlHours: 12,
  adminIdleMinutes: 60,
})

const positiveWhole = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 1

/**
 * The instance's lifetimes (identity switch on). A missing row or a value that is not a whole
 * number from 1 reads as its default; the policy form keeps writes inside its bounds, but a host
 * may set a row by hand. A failed read never fails a sign-in: the defaults apply and the code is
 * logged (never the message, which may quote an address).
 */
export async function sessionLifetimes(): Promise<SessionLifetimes> {
  try {
    const row = await prisma.instanceSettings.findUnique({
      where: { id: INSTANCE_SETTINGS_ROW },
      select: { memberSessionTtlHours: true, adminSessionTtlHours: true, adminIdleMinutes: true },
    })
    const pick = (k: keyof SessionLifetimes) => (positiveWhole(row?.[k]) ? row![k] : LIFETIME_DEFAULTS[k])
    return {
      memberSessionTtlHours: pick('memberSessionTtlHours'),
      adminSessionTtlHours: pick('adminSessionTtlHours'),
      adminIdleMinutes: pick('adminIdleMinutes'),
    }
  } catch (err) {
    console.error(`[rbac] session lifetime read failed code=${safeErrorCode(err)}`)
    return { ...LIFETIME_DEFAULTS }
  }
}

/**
 * The browser a login token is for (step 6.10): `meta` describes it (address, browser), `keep` is the
 * device session its current cookie names, carried over by a re-issue (a password change).
 */
export interface LoginDevice {
  meta: ClientMeta
  keep?: string | null
}

/**
 * A login token for `account` and how long its cookie lives: at sign-in, at an invite accept and
 * when a password change re-issues it. `pwc` is the must-change claim (step 2.8), which like the
 * lifetimes exists only with the switch on. With the governance switch on and a `device`, the token
 * names that browser's device session (`sid`): the kept one when it is still this account's live row,
 * else a new one. Writing the row can fail: then no token is issued (the caller answers 500).
 */
export async function issueLoginToken(
  account: { id: string; role: string; sessionVersion: number },
  { pwc = false, device }: { pwc?: boolean; device?: LoginDevice } = {},
): Promise<{ token: string; maxAge: number }> {
  if (!rbacFlags().identity) {
    return { token: await createToken(account.id, account.role, account.sessionVersion), maxAge: PHASE1_LOGIN_SECONDS }
  }
  const lifetimes = await sessionLifetimes()
  const admin = account.role === 'admin'
  const seconds = (admin ? lifetimes.adminSessionTtlHours : lifetimes.memberSessionTtlHours) * HOUR
  const sid = device && deviceSessionsInForce() ? await deviceSessionFor(account, device, seconds) : undefined
  const token = await createToken(account.id, account.role, account.sessionVersion, {
    pwc,
    lifetime: { seconds, admin, idleMinutes: admin ? lifetimes.adminIdleMinutes : null },
    ...(sid ? { sid } : {}),
  })
  return { token, maxAge: seconds }
}

async function deviceSessionFor(account: { id: string; sessionVersion: number }, device: LoginDevice, seconds: number): Promise<string> {
  const expiresAt = new Date(now().getTime() + seconds * 1000)
  if (device.keep && (await keepDeviceSession(device.keep, account, expiresAt))) return device.keep
  return openDeviceSession(account, device.meta, expiresAt)
}

/**
 * How long an act-as cookie lives: as long as an admin session, never longer than Phase 1's
 * 12 h (Phase 3's impersonation bound, `impersonationMaxMinutes`, takes over there).
 */
export async function actAsLifetimeSeconds(): Promise<number> {
  if (!rbacFlags().identity) return PHASE1_ACT_AS_SECONDS
  return Math.min((await sessionLifetimes()).adminSessionTtlHours * HOUR, PHASE1_ACT_AS_SECONDS)
}
