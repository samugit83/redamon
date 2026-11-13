/**
 * Device sessions (step 6.10, GV-17): the row a sign-in writes and its id in the login token (`sid`),
 * the check getSession makes (revoked or unknown refused, cached for RBAC_AUTHZ_CACHE_MS), the
 * 5-minute `lastSeenAt` throttle, the state a row reads as, sign-out's end, and the sweep's 30 days.
 * With RBAC_GOVERNANCE_ENABLED off no row is written and no token names one (DV-30).
 *
 * The database is the in-memory accountDb; time comes from the authz clock.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/deviceSessions.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { SignJWT, decodeJwt } from 'jose'

vi.stubEnv('AUTH_SECRET', 'd'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('./__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from './__testing__/accountDb'
import { createToken, verifyToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearPrincipalCacheForTests } from './principal'
import { issueLoginToken } from './sessionLifetime'
import {
  DEVICE_SESSION_KEEP_DAYS, LAST_SEEN_EVERY_MS, clearDeviceSessionCacheForTests, deviceSessionRefusal, deviceSessionState,
  endDeviceSessionAtSignOut, invalidateDeviceSession, isDeviceSessionId, sweepDeviceSessions,
} from './deviceSessions'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-13T12:00:00Z')
const HOUR = 3600_000
const DAY = 24 * HOUR
const at = (ms: number) => setNowForTests(() => new Date(T0.getTime() + ms))
const GOVERNANCE = { identity: true, permissions: true, governance: true }
const META = { ip: '203.0.113.7', ipTrusted: true, userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0' }
const member = { id: 'm1', role: 'standard', sessionVersion: 3 }

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'm1', sessionVersion: 3 }, { id: 'm2' }])
  setFlagsForTests(GOVERNANCE)
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  clearDeviceSessionCacheForTests()
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  vi.stubEnv('AUTH_SECRET', 'd'.repeat(64))
})

describe('login creates a session', () => {
  test('a sign-in writes one row for the browser and its id rides in the token as sid', async () => {
    const { token, maxAge } = await issueLoginToken(member, { device: { meta: META } })
    const rows = db().sessions()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      userId: 'm1', sessionVersion: 3, ip: '203.0.113.7', ipTrusted: true, userAgent: META.userAgent,
      createdAt: T0, lastSeenAt: T0, expiresAt: new Date(T0.getTime() + maxAge * 1000), revokedAt: null,
    })
    expect(decodeJwt(token).sid).toBe(rows[0].id)
    expect(await verifyToken(token)).toEqual({ sub: 'm1', role: 'standard', sv: 3, sid: rows[0].id })
  })

  test('two sign-ins are two sessions', async () => {
    const a = decodeJwt((await issueLoginToken(member, { device: { meta: META } })).token).sid
    const b = decodeJwt((await issueLoginToken(member, { device: { meta: { ...META, ip: null } } })).token).sid
    expect(a).not.toBe(b)
    expect(db().sessions().map((r) => r.id)).toEqual([a, b])
  })

  test('an address and a browser header are cut to their stored lengths', async () => {
    await issueLoginToken(member, { device: { meta: { ip: '1'.repeat(300), ipTrusted: false, userAgent: 'x'.repeat(2000) } } })
    const [row] = db().sessions()
    expect(String(row.ip)).toHaveLength(100)
    expect(String(row.userAgent)).toHaveLength(512)
  })

  test('switch off (identity and permissions on): no row is written and the token carries no sid', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    const { token } = await issueLoginToken(member, { device: { meta: META } })
    expect(db().sessions()).toEqual([])
    expect(decodeJwt(token)).not.toHaveProperty('sid')
    setFlagsForTests({})
    expect(decodeJwt((await issueLoginToken(member, { device: { meta: META } })).token)).not.toHaveProperty('sid')
    expect(db().sessions()).toEqual([])
  })

  test('a writer that names no browser gets no sid', async () => {
    expect(decodeJwt((await issueLoginToken(member)).token)).not.toHaveProperty('sid')
    expect(db().sessions()).toEqual([])
  })

  test('the row cannot be written: no token is issued', async () => {
    vi.spyOn(db().userSession, 'create').mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(issueLoginToken(member, { device: { meta: META } })).rejects.toThrow('db down')
  })

  test('a password change re-issue keeps the browser\'s row: same sid, new version and expiry', async () => {
    db().seedSession({ id: 'sess-old', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + HOUR) })
    at(10 * 60_000)
    const { token, maxAge } = await issueLoginToken({ ...member, sessionVersion: 3 }, { device: { meta: META, keep: 'sess-old' } })
    expect(decodeJwt(token).sid).toBe('sess-old')
    expect(db().sessions()).toHaveLength(1)
    expect(db().sessions()[0]).toMatchObject({ expiresAt: new Date(T0.getTime() + 10 * 60_000 + maxAge * 1000), lastSeenAt: new Date(T0.getTime() + 10 * 60_000) })
  })

  test('a re-issue never revives a revoked row, nor takes another account\'s: a new row instead', async () => {
    db().seedSession({ id: 'sess-gone', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + HOUR), revokedAt: T0 })
    db().seedSession({ id: 'sess-m2', userId: 'm2', sessionVersion: 0, expiresAt: new Date(T0.getTime() + HOUR) })
    for (const keep of ['sess-gone', 'sess-m2']) {
      const sid = decodeJwt((await issueLoginToken(member, { device: { meta: META, keep } })).token).sid
      expect(sid).not.toBe(keep)
    }
    expect(db().sessions().find((r) => r.id === 'sess-gone')?.revokedAt).toEqual(T0)
    expect(db().sessions()).toHaveLength(4)
  })
})

describe('the sid claim', () => {
  const KEY = new TextEncoder().encode('d'.repeat(64))
  test('createToken refuses anything but a short id', async () => {
    await expect(createToken('m1', 'standard', 0, { sid: '' })).rejects.toThrow()
    await expect(createToken('m1', 'standard', 0, { sid: 'a b' })).rejects.toThrow()
    await expect(createToken('m1', 'standard', 0, { sid: 'x'.repeat(65) })).rejects.toThrow()
    expect(isDeviceSessionId('ckabc123_-Z')).toBe(true)
    expect(isDeviceSessionId('../x')).toBe(false)
  })

  test('a token whose sid is malformed is invalid; a token without one is as before', async () => {
    for (const sid of [42, '', 'a/b', ['x']]) {
      const forged = await new SignJWT({ sub: 'm1', role: 'standard', sv: 0, sid }).setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt().setExpirationTime('1h').sign(KEY)
      expect(await verifyToken(forged)).toBeNull()
    }
    expect(await verifyToken(await createToken('m1', 'standard', 2))).toEqual({ sub: 'm1', role: 'standard', sv: 2 })
  })
})

describe('revoked sid refused', () => {
  beforeEach(() => {
    db().seedSession({ id: 'sess-1', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY), createdAt: T0 })
  })

  test('a live row passes; a revoked one, a signed-out one, a missing one or another account\'s is refused', async () => {
    expect(await deviceSessionRefusal('sess-1', 'm1')).toBeNull()
    expect(await deviceSessionRefusal('sess-1', 'm2')).toBe('unknown')
    expect(await deviceSessionRefusal('sess-404', 'm1')).toBe('unknown')
    db().seedSession({ id: 'sess-2', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY), revokedAt: T0, endedBy: 'admin' })
    db().seedSession({ id: 'sess-3', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY), revokedAt: T0, endedBy: 'sign_out' })
    expect(await deviceSessionRefusal('sess-2', 'm1')).toBe('revoked')
    expect(await deviceSessionRefusal('sess-3', 'm1')).toBe('revoked')
  })

  test('another copy\'s revoke lands within the cache bound; this process\'s at once; fresh reads past the cache', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '5000')
    expect(await deviceSessionRefusal('sess-1', 'm1')).toBeNull()
    await db().userSession.updateMany({ where: { id: 'sess-1' }, data: { revokedAt: T0 } })
    // Still within the bound: this copy holds the row it read.
    at(4_000)
    expect(await deviceSessionRefusal('sess-1', 'm1')).toBeNull()
    expect(await deviceSessionRefusal('sess-1', 'm1', { fresh: true })).toBe('revoked')
    clearDeviceSessionCacheForTests()
    at(0)
    db().seedSession({ id: 'sess-b', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY), createdAt: T0 })
    expect(await deviceSessionRefusal('sess-b', 'm1')).toBeNull()
    await db().userSession.updateMany({ where: { id: 'sess-b' }, data: { revokedAt: T0 } })
    at(5_001)
    expect(await deviceSessionRefusal('sess-b', 'm1')).toBe('revoked')
    db().seedSession({ id: 'sess-c', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY), createdAt: T0 })
    expect(await deviceSessionRefusal('sess-c', 'm1')).toBeNull()
    await db().userSession.updateMany({ where: { id: 'sess-c' }, data: { revokedAt: T0 } })
    invalidateDeviceSession('sess-c')
    expect(await deviceSessionRefusal('sess-c', 'm1')).toBe('revoked')
  })

  test('with the cache off (RBAC_AUTHZ_CACHE_MS=0) every check reads the row', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '0')
    const reads = vi.spyOn(db().userSession, 'findUnique')
    await deviceSessionRefusal('sess-1', 'm1')
    await deviceSessionRefusal('sess-1', 'm1')
    expect(reads).toHaveBeenCalledTimes(2)
  })

  test('a failed read throws: it never reads as signed in', async () => {
    vi.spyOn(db().userSession, 'findUnique').mockRejectedValueOnce(new Error('db down'))
    await expect(deviceSessionRefusal('sess-1', 'm1')).rejects.toThrow('db down')
  })
})

describe('lastSeenAt throttled', () => {
  beforeEach(() => {
    db().seedSession({ id: 'sess-1', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY), createdAt: T0 })
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '0')
  })
  const seen = () => db().sessions()[0].lastSeenAt as Date

  test('no write within 5 minutes; one once older; none again until the next interval', async () => {
    const writes = vi.spyOn(db().userSession, 'updateMany')
    at(LAST_SEEN_EVERY_MS)
    await deviceSessionRefusal('sess-1', 'm1')
    expect(writes).not.toHaveBeenCalled()
    expect(seen()).toEqual(T0)
    at(LAST_SEEN_EVERY_MS + 1_000)
    await deviceSessionRefusal('sess-1', 'm1')
    expect(writes).toHaveBeenCalledTimes(1)
    expect(seen()).toEqual(new Date(T0.getTime() + LAST_SEEN_EVERY_MS + 1_000))
    at(2 * LAST_SEEN_EVERY_MS)
    await deviceSessionRefusal('sess-1', 'm1')
    expect(writes).toHaveBeenCalledTimes(1)
  })

  test('two copies past the interval at once: the conditional write moves it once', async () => {
    at(LAST_SEEN_EVERY_MS + 1_000)
    await Promise.all([deviceSessionRefusal('sess-1', 'm1'), deviceSessionRefusal('sess-1', 'm1')])
    expect(seen()).toEqual(new Date(T0.getTime() + LAST_SEEN_EVERY_MS + 1_000))
  })

  test('a failed write is logged with its code and the request goes on', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(db().userSession, 'updateMany').mockRejectedValueOnce(Object.assign(new Error('connect 10.0.0.9'), { code: 'P1001' }))
    at(LAST_SEEN_EVERY_MS + 1_000)
    expect(await deviceSessionRefusal('sess-1', 'm1')).toBeNull()
    expect(error).toHaveBeenCalledWith('[rbac] device session last-seen update failed code=P1001')
    expect(String(error.mock.calls)).not.toContain('10.0.0.9')
  })
})

describe('what a row reads as', () => {
  const row = (over: Record<string, unknown> = {}) => ({
    sessionVersion: 3, expiresAt: new Date(T0.getTime() + HOUR), revokedAt: null, endedBy: null, ...over,
  }) as { sessionVersion: number; expiresAt: Date; revokedAt: Date | null; endedBy: string | null }

  test.each([
    ['live', row(), 3, 'active'],
    ['revoked by the account or an admin', row({ revokedAt: T0, endedBy: 'self' }), 3, 'revoked'],
    ['signed out', row({ revokedAt: T0, endedBy: 'sign_out' }), 3, 'signed_out'],
    ['below the account\'s version (sign out everywhere, a disable, a reset)', row(), 4, 'ended'],
    ['past its expiry', row({ expiresAt: T0 }), 3, 'expired'],
  ])('%s', (_name, r, version, state) => {
    expect(deviceSessionState(r, version as number, T0)).toBe(state)
  })
})

describe('sign-out ends the row', () => {
  test('signed_out, by the account; a second sign-out changes nothing', async () => {
    db().seedSession({ id: 'sess-1', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY) })
    await endDeviceSessionAtSignOut('sess-1', 'm1')
    expect(db().sessions()[0]).toMatchObject({ revokedAt: T0, revokedById: 'm1', endedBy: 'sign_out' })
    at(60_000)
    await endDeviceSessionAtSignOut('sess-1', 'm1')
    expect(db().sessions()[0].revokedAt).toEqual(T0)
    expect(await deviceSessionRefusal('sess-1', 'm1')).toBe('revoked')
  })

  test('never another account\'s row; a failed write is logged and never thrown', async () => {
    db().seedSession({ id: 'sess-2', userId: 'm2', sessionVersion: 0, expiresAt: new Date(T0.getTime() + DAY) })
    await endDeviceSessionAtSignOut('sess-2', 'm1')
    expect(db().sessions()[0].revokedAt).toBeNull()
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(db().userSession, 'updateMany').mockRejectedValueOnce(Object.assign(new Error('x'), { code: 'P1001' }))
    await expect(endDeviceSessionAtSignOut('sess-2', 'm2')).resolves.toBeUndefined()
    expect(error).toHaveBeenCalledWith('[rbac] device session not ended at sign-out code=P1001')
  })
})

describe('sweep removes old rows', () => {
  test(`a row revoked or expired more than ${DEVICE_SESSION_KEEP_DAYS} days ago goes; younger ones and live ones stay`, async () => {
    const cutoff = new Date(T0.getTime() - DEVICE_SESSION_KEEP_DAYS * DAY)
    const later = new Date(T0.getTime() + DAY)
    db().seedSession({ id: 'revoked-old', userId: 'm1', sessionVersion: 3, expiresAt: later, revokedAt: new Date(cutoff.getTime() - 1) })
    db().seedSession({ id: 'revoked-at-cutoff', userId: 'm1', sessionVersion: 3, expiresAt: later, revokedAt: cutoff })
    db().seedSession({ id: 'expired-old', userId: 'm1', sessionVersion: 3, expiresAt: new Date(cutoff.getTime() - DAY) })
    db().seedSession({ id: 'revoked-young', userId: 'm1', sessionVersion: 3, expiresAt: later, revokedAt: new Date(cutoff.getTime() + 1) })
    db().seedSession({ id: 'expired-young', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() - DAY) })
    db().seedSession({ id: 'live', userId: 'm2', sessionVersion: 0, expiresAt: later })
    expect(await sweepDeviceSessions(T0)).toBe(3)
    expect(db().sessions().map((r) => r.id).sort()).toEqual(['expired-young', 'live', 'revoked-young'])
    expect(await sweepDeviceSessions(T0)).toBe(0)
  })

  test('a row goes with its account', async () => {
    db().seedSession({ id: 'sess-1', userId: 'm1', sessionVersion: 3, expiresAt: new Date(T0.getTime() + DAY) })
    await db().user.delete({ where: { id: 'm1' } })
    expect(db().sessions()).toEqual([])
  })
})
