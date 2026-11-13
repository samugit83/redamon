/**
 * Device sessions (step 6.10, GV-17, UI-09): one `UserSession` row per browser sign-in, its id in the
 * login token as `sid`, so one browser can be signed out while the account's others go on.
 *
 * With RBAC_GOVERNANCE_ENABLED on:
 *   - a sign-in, an invite accept and a password change's re-issue write or keep the row
 *     (sessionLifetime.ts issueLoginToken);
 *   - getSession refuses a token whose row is revoked or gone (`deviceSessionRefusal`). The row is
 *     read with the account and kept per process for RBAC_AUTHZ_CACHE_MS, as the principal is, so a
 *     revoke made in another webapp copy lands within that bound; a revoke in this process drops the
 *     entry at once (`invalidateDeviceSession`);
 *   - `lastSeenAt` moves at most every 5 minutes, by a write conditional on the old value, so two
 *     copies never both write it;
 *   - the expiry sweep deletes a row 30 days after it was revoked or expired (`sweepDeviceSessions`).
 * A token without `sid` (signed before the switch, the Playwright helper's) stays valid until the
 * account's session version moves. A version bump ends every row of the account without touching it:
 * a row whose `sessionVersion` is below the account's reads as ended (`deviceSessionState`).
 *
 * Off: no row is written, no token carries `sid`, nothing is read or checked, and an existing `sid`
 * claim is ignored (DV-30). The Edge middleware cannot read the table (T2), so a revoked cookie still
 * loads pages while every API answers 401 `session_ended` and the browser goes to /login (as with `sv`).
 *
 * Server only; never imports lib/session.ts (which imports this).
 */
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import type { ClientMeta } from '@/lib/requestMeta'
import { now } from './clock'
import { rbacFlags } from './flags'
import { principalCacheTtl } from './principal'

/** `lastSeenAt` moves at most this often. */
export const LAST_SEEN_EVERY_MS = 5 * 60 * 1000
/** PLACEHOLDER(OQ-38): how long an ended row (its address and browser) is kept before the sweep deletes it. */
export const DEVICE_SESSION_KEEP_DAYS = 30
const DAY_MS = 24 * 60 * 60 * 1000
// Stored values are cut to these lengths: a header can be as long as the client likes.
const MAX_USER_AGENT = 512
const MAX_IP = 100
// A cuid; anything else (a forged claim cannot get here, a hand-typed URL can) is no session.
const SESSION_ID = /^[A-Za-z0-9_-]{1,64}$/
// One entry per live browser that sent a request recently, as the principal cache.
const MAX_ENTRIES = 10_000

export type EndedBy = 'sign_out' | 'self' | 'admin'
export type DeviceSessionState = 'active' | 'revoked' | 'signed_out' | 'ended' | 'expired'

export function deviceSessionsInForce(): boolean {
  return rbacFlags().governance
}

export function isDeviceSessionId(v: unknown): v is string {
  return typeof v === 'string' && SESSION_ID.test(v)
}

const cut = (v: string | null, max: number) => (v ? v.slice(0, max) : null)

interface AccountVersion {
  id: string
  sessionVersion: number
}

/** A new row for a sign-in from the browser `meta` describes; its id is the token's `sid`. */
export async function openDeviceSession(account: AccountVersion, meta: ClientMeta, expiresAt: Date): Promise<string> {
  const at = now()
  const row = await prisma.userSession.create({
    data: {
      userId: account.id,
      sessionVersion: account.sessionVersion,
      createdAt: at,
      lastSeenAt: at,
      expiresAt,
      ip: cut(meta.ip, MAX_IP),
      ipTrusted: meta.ipTrusted,
      userAgent: cut(meta.userAgent, MAX_USER_AGENT),
    },
    select: { id: true },
  })
  return row.id
}

/**
 * The browser's own row carried over to a re-issued token (a password change): the new version and
 * expiry are written to it. False when the row is not this account's live one, so the caller opens
 * a new one rather than reviving a revoked session.
 */
export async function keepDeviceSession(sid: string, account: AccountVersion, expiresAt: Date): Promise<boolean> {
  const { count } = await prisma.userSession.updateMany({
    where: { id: sid, userId: account.id, revokedAt: null },
    data: { sessionVersion: account.sessionVersion, expiresAt, lastSeenAt: now() },
  })
  invalidateDeviceSession(sid)
  return count === 1
}

// --- the check ------------------------------------------------------------------------------------

interface RowState {
  userId: string
  revoked: boolean
  lastSeenAt: Date
}

const cache = new Map<string, { state: RowState | null; expiresAt: number }>()
// Raised by every invalidation: a read that started before one may hold the revoked row as live.
let generation = 0

async function readRow(sid: string): Promise<RowState | null> {
  const row = await prisma.userSession.findUnique({
    where: { id: sid },
    select: { userId: true, revokedAt: true, lastSeenAt: true },
  })
  return row ? { userId: row.userId, revoked: row.revokedAt !== null, lastSeenAt: row.lastSeenAt } : null
}

function remember(sid: string, state: RowState | null, ttl: number): void {
  const at = now().getTime()
  if (cache.size >= MAX_ENTRIES && !cache.has(sid)) {
    for (const [id, entry] of cache) if (entry.expiresAt <= at) cache.delete(id)
    if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value as string)
  }
  cache.set(sid, { state, expiresAt: at + ttl })
}

async function rowState(sid: string, fresh: boolean): Promise<RowState | null> {
  const ttl = principalCacheTtl()
  if (!fresh && ttl > 0) {
    const hit = cache.get(sid)
    if (hit && hit.expiresAt > now().getTime()) return hit.state
  }
  const startedAt = generation
  const state = await readRow(sid)
  if (ttl > 0 && startedAt === generation) remember(sid, state, ttl)
  else cache.delete(sid)
  return state
}

/**
 * Moves `lastSeenAt` once it is more than LAST_SEEN_EVERY_MS old. Never fails the request it rides
 * on: a failed write is logged with its code and tried again after the next interval.
 */
async function touch(sid: string, state: RowState): Promise<void> {
  const at = now()
  const stale = new Date(at.getTime() - LAST_SEEN_EVERY_MS)
  if (state.lastSeenAt.getTime() >= stale.getTime()) return
  // Whatever the write does, this process waits out the interval before trying again.
  state.lastSeenAt = at
  try {
    await prisma.userSession.updateMany({
      where: { id: sid, revokedAt: null, lastSeenAt: { lt: stale } },
      data: { lastSeenAt: at },
    })
  } catch (err) {
    console.error(`[rbac] device session last-seen update failed code=${safeErrorCode(err)}`)
  }
}

/**
 * Why getSession refuses the login token carrying `sid` for account `userId`: `revoked` (the row
 * was revoked or signed out), `unknown` (no such row for this account: swept, deleted, or the table
 * pushed away by a downgrade), or null when the session goes on. `fresh` reads past the cache. A
 * failed read throws: it never reads as signed in.
 */
export async function deviceSessionRefusal(
  sid: string, userId: string, { fresh = false }: { fresh?: boolean } = {},
): Promise<'revoked' | 'unknown' | null> {
  const state = await rowState(sid, fresh)
  if (!state || state.userId !== userId) return 'unknown'
  if (state.revoked) return 'revoked'
  await touch(sid, state)
  return null
}

/** A writer in this process revoked or changed the row: the next check reads the database. */
export function invalidateDeviceSession(sid: string): void {
  generation += 1
  cache.delete(sid)
}

/** Tests only: forget every row. */
export function clearDeviceSessionCacheForTests(): void {
  generation += 1
  cache.clear()
}

// --- the session object's device ------------------------------------------------------------------

const devices = new WeakMap<object, string>()

/** getSession records the `sid` of the token it accepted (switch on), beside the session object. */
export function rememberSessionDevice(session: object, sid: string | null): void {
  if (sid) devices.set(session, sid)
}

/** The device session a session object's login token names, or null (switch off, no `sid`, a hand-made session). */
export function sessionDeviceId(session: object): string | null {
  return devices.get(session) ?? null
}

// --- ending and reading rows ------------------------------------------------------------------------

/**
 * Sign-out ends the browser's row (`signed_out`), so the list stops showing it as live and a copy of
 * the cookie is refused from now on. Never throws: signing out never fails (logged with its code).
 */
export async function endDeviceSessionAtSignOut(sid: string, userId: string): Promise<void> {
  try {
    await prisma.userSession.updateMany({
      where: { id: sid, userId, revokedAt: null },
      data: { revokedAt: now(), revokedById: userId, endedBy: 'sign_out' },
    })
  } catch (err) {
    console.error(`[rbac] device session not ended at sign-out code=${safeErrorCode(err)}`)
  } finally {
    invalidateDeviceSession(sid)
  }
}

/** What a row is now, for the account whose session version is `accountVersion`. */
export function deviceSessionState(
  row: { sessionVersion: number; expiresAt: Date; revokedAt: Date | null; endedBy: string | null },
  accountVersion: number,
  at: Date = now(),
): DeviceSessionState {
  if (row.revokedAt) return row.endedBy === 'sign_out' ? 'signed_out' : 'revoked'
  if (row.sessionVersion < accountVersion) return 'ended'
  if (row.expiresAt.getTime() <= at.getTime()) return 'expired'
  return 'active'
}

/** The rows older than this when ended are deleted. */
export function deviceSessionCutoff(at: Date): Date {
  return new Date(at.getTime() - DEVICE_SESSION_KEEP_DAYS * DAY_MS)
}

/**
 * The expiry sweep's part (governance on): deletes every row revoked or expired more than
 * DEVICE_SESSION_KEEP_DAYS ago, with its address and browser. A row ended by a version bump ages out
 * with its token's expiry. Idempotent: a second sweep, or another copy's, finds nothing more.
 */
export async function sweepDeviceSessions(at: Date): Promise<number> {
  const cutoff = deviceSessionCutoff(at)
  const revoked = await prisma.userSession.deleteMany({ where: { revokedAt: { lte: cutoff } } })
  const expired = await prisma.userSession.deleteMany({ where: { expiresAt: { lte: cutoff } } })
  return revoked.count + expired.count
}
