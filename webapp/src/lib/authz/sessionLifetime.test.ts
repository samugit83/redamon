/**
 * Session lifetimes (step 2.11, ID-24; feature document §7.1 "privileged sessions are shorter ...
 * and an idle timeout, both set by Root"). With the identity switch on, a login token lives
 * `memberSessionTtlHours` for a member and `adminSessionTtlHours` for Root and admins, read from
 * the instance settings row (schema defaults 168 h, 12 h and 60 min, PLACEHOLDER(OQ-38), when the
 * row or a value is missing); an admin's token also carries `adm`, its idle limit `idl` (minutes)
 * and its last activity `lat`; the cookie lives as long as the token. Act-as lives as long as an
 * admin session, never longer than today's 12 h (Phase 3 brings its own bound). A failed read
 * never fails a sign-in: the defaults apply and the code is logged. With the switch off: today's
 * 7-day token with `{sub, role, sv, iat, exp}` only, 12 h act-as, and nothing read.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { SignJWT, decodeJwt } from 'jose'

vi.stubEnv('AUTH_SECRET', 'l'.repeat(64))

const h = vi.hoisted(() => ({
  row: null as Record<string, unknown> | null,
  reads: [] as unknown[],
  fail: false,
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    instanceSettings: {
      findUnique: async (a: unknown) => {
        h.reads.push(a)
        if (h.fail) throw Object.assign(new Error('connect ECONNREFUSED 10.1.2.3'), { code: 'P1001' })
        return h.row
      },
    },
  },
}))

import { createActAsToken, verifyActAsToken, verifyToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import {
  LIFETIME_DEFAULTS,
  PHASE1_ACT_AS_SECONDS,
  PHASE1_LOGIN_SECONDS,
  actAsLifetimeSeconds,
  issueLoginToken,
  sessionLifetimes,
} from './sessionLifetime'

const HOUR = 60 * 60
const member = { id: 'm1', role: 'standard', sessionVersion: 2 }
const admin = { id: 'a1', role: 'admin', sessionVersion: 5 }

beforeEach(() => {
  h.row = null
  h.reads = []
  h.fail = false
  setFlagsForTests({ identity: true })
})
afterEach(() => setFlagsForTests(null))

describe('admin token expires at 12 h, member at 168 h (placeholders)', () => {
  test('the schema defaults are the OQ-38 placeholders', () => {
    expect(LIFETIME_DEFAULTS).toEqual({ memberSessionTtlHours: 168, adminSessionTtlHours: 12, adminIdleMinutes: 60 })
  })

  test('no instance row: a member token lives 168 h and carries no admin claim', async () => {
    const { token, maxAge } = await issueLoginToken(member)
    const c = decodeJwt(token)
    expect(c.exp! - c.iat!).toBe(168 * HOUR)
    expect(maxAge).toBe(168 * HOUR)
    expect(Object.keys(c).sort()).toEqual(['exp', 'iat', 'role', 'sub', 'sv'])
    expect(await verifyToken(token)).toEqual({ sub: 'm1', role: 'standard', sv: 2 })
  })

  test('an admin token lives 12 h and carries adm, idl (60) and lat = iat', async () => {
    const { token, maxAge } = await issueLoginToken(admin)
    const c = decodeJwt(token)
    expect(c.exp! - c.iat!).toBe(12 * HOUR)
    expect(maxAge).toBe(12 * HOUR)
    expect(c).toMatchObject({ sub: 'a1', role: 'admin', sv: 5, adm: 1, idl: 60, lat: c.iat })
    expect(await verifyToken(token)).toEqual({ sub: 'a1', role: 'admin', sv: 5 })
  })

  test("Root's values from the instance row", async () => {
    h.row = { memberSessionTtlHours: 24, adminSessionTtlHours: 2, adminIdleMinutes: 15 }
    const m = decodeJwt((await issueLoginToken(member)).token)
    expect(m.exp! - m.iat!).toBe(24 * HOUR)
    const a = await issueLoginToken(admin)
    const c = decodeJwt(a.token)
    expect(c.exp! - c.iat!).toBe(2 * HOUR)
    expect(a.maxAge).toBe(2 * HOUR)
    expect(c.idl).toBe(15)
    expect(h.reads).toEqual([
      { where: { id: 'instance' }, select: { memberSessionTtlHours: true, adminSessionTtlHours: true, adminIdleMinutes: true } },
      { where: { id: 'instance' }, select: { memberSessionTtlHours: true, adminSessionTtlHours: true, adminIdleMinutes: true } },
    ])
  })

  test('a stored value that is not a whole number from 1 reads as its default', async () => {
    h.row = { memberSessionTtlHours: 0, adminSessionTtlHours: -3, adminIdleMinutes: 1.5 }
    expect(await sessionLifetimes()).toEqual(LIFETIME_DEFAULTS)
    h.row = { memberSessionTtlHours: null, adminSessionTtlHours: '4', adminIdleMinutes: 1 }
    // 1 minute is below what the policy form accepts (5), but a host may set it in the row (E2E-P2-09).
    expect(await sessionLifetimes()).toEqual({ memberSessionTtlHours: 168, adminSessionTtlHours: 12, adminIdleMinutes: 1 })
  })

  test('the must-change claim is carried alongside', async () => {
    const c = decodeJwt((await issueLoginToken(admin, { pwc: true })).token)
    expect(c).toMatchObject({ pwc: 1, adm: 1, idl: 60 })
  })

  test('a failed read never fails a sign-in: the defaults, and the code logged', async () => {
    h.fail = true
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const c = decodeJwt((await issueLoginToken(admin)).token)
      expect(c.exp! - c.iat!).toBe(12 * HOUR)
      expect(c.idl).toBe(60)
      expect(err).toHaveBeenCalledWith('[rbac] session lifetime read failed code=P1001')
      expect(err.mock.calls.flat().join(' ')).not.toContain('10.1.2.3')
    } finally {
      err.mockRestore()
    }
  })
})

describe('act-as lives as long as an admin session, at most 12 h', () => {
  test('default 12 h; a shorter admin session shortens it; a longer one does not lengthen it', async () => {
    expect(await actAsLifetimeSeconds()).toBe(12 * HOUR)
    h.row = { adminSessionTtlHours: 3 }
    expect(await actAsLifetimeSeconds()).toBe(3 * HOUR)
    h.row = { adminSessionTtlHours: 48 }
    expect(await actAsLifetimeSeconds()).toBe(12 * HOUR)
  })

  test('the act-as token expires when its cookie does', async () => {
    h.row = { adminSessionTtlHours: 3 }
    const seconds = await actAsLifetimeSeconds()
    const token = await createActAsToken('a1', 'm1', seconds)
    const c = decodeJwt(token)
    expect(c.exp! - c.iat!).toBe(3 * HOUR)
    expect(await verifyActAsToken(token)).toEqual({ sub: 'a1', act: 'm1' })
  })
})

describe('switch off → today\'s 7 days, no idle', () => {
  beforeEach(() => setFlagsForTests({ identity: false }))

  test('every login token lives 7 days with the Phase 1 claims; nothing is read', async () => {
    h.row = { memberSessionTtlHours: 1, adminSessionTtlHours: 1, adminIdleMinutes: 5 }
    for (const account of [member, admin]) {
      const { token, maxAge } = await issueLoginToken(account, { pwc: true })
      const c = decodeJwt(token)
      expect(c.exp! - c.iat!).toBe(7 * 24 * HOUR)
      expect(maxAge).toBe(PHASE1_LOGIN_SECONDS)
      expect(Object.keys(c).sort()).toEqual(['exp', 'iat', 'role', 'sub', 'sv'])
    }
    expect(await actAsLifetimeSeconds()).toBe(PHASE1_ACT_AS_SECONDS)
    expect(PHASE1_LOGIN_SECONDS).toBe(7 * 24 * HOUR)
    expect(PHASE1_ACT_AS_SECONDS).toBe(12 * HOUR)
    expect(h.reads).toEqual([])
  })

  test('act-as tokens keep their 12 h', async () => {
    const c = decodeJwt(await createActAsToken('a1', 'm1'))
    expect(c.exp! - c.iat!).toBe(12 * HOUR)
  })
})

describe('the claims a login token may carry', () => {
  test('adm other than 1, or idle claims that are not whole numbers, make the token invalid', async () => {
    const sign = (claims: Record<string, unknown>) => new SignJWT({ sub: 'a1', role: 'admin', sv: 0, ...claims })
      .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h').sign(new TextEncoder().encode('l'.repeat(64)))
    const now = Math.floor(Date.now() / 1000)
    for (const bad of [
      { adm: 2 }, { adm: true }, { idl: 0, lat: now }, { idl: 60, lat: 'x' }, { idl: 1.5, lat: now },
      { idl: 60 }, { lat: now },
    ]) {
      expect(await verifyToken(await sign(bad))).toBeNull()
    }
    expect(await verifyToken(await sign({ adm: 1, idl: 60, lat: now }))).toEqual({ sub: 'a1', role: 'admin', sv: 0 })
  })
})
