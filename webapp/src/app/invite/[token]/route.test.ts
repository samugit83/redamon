/**
 * GET /invite/<token> (step 2.9, ID-15, DV-05), public: the link a person was sent. It trades the
 * token for a 30-minute signed httpOnly cookie naming the link and redirects 303 to `/invite`, so
 * the token leaves the address bar and the history and is never sent on as a referrer. An
 * unknown, expired, used or cancelled token gets the same redirect without a cookie (the page
 * then shows its one "not valid or has expired" message). Lookups are capped per copy (30 a
 * minute) whatever the client address. With the identity switch off: 404.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { resetInviteLimitsForTests } from '@/lib/authz/inviteLimits'
import { createLink, newLinkToken, readInviteCookie } from '@/lib/authz/invites'
import { GET } from './route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')
let clock = T0
const tokenOf = (link: string) => link.slice(link.lastIndexOf('/') + 1)

async function openLink(userId = 'invited-1') {
  return db().$transaction((tx) => createLink(tx as never, { userId, kind: 'invite', createdById: 'admin-1' }))
}

function open(token: string, headers: Record<string, string> = {}) {
  return GET(new NextRequest(`http://redamon.test/invite/${token}`, { headers: { host: 'redamon.test', ...headers } }), {
    params: Promise.resolve({ token }),
  })
}

const inviteCookie = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith('redamon-invite='))

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'invited-1', status: 'invited', password: '' }])
  db().seedInstance({ inviteTtlHours: 168, publicBaseUrl: 'https://redamon.example.com' })
  setFlagsForTests({ identity: true })
  clock = T0
  setNowForTests(() => clock)
  resetInviteLimitsForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('a valid link', () => {
  test('sets the 30-minute httpOnly cookie naming the link and redirects 303 to /invite', async () => {
    const made = await openLink()
    const res = await open(tokenOf(made.link))
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe('/invite')
    const cookie = inviteCookie(res)!
    expect(cookie).toMatch(/HttpOnly/i)
    expect(cookie).toMatch(/Max-Age=1800/i)
    expect(cookie).toMatch(/Path=\/api\/invite/i)
    expect(cookie).toMatch(/SameSite=lax/i)
    expect(await readInviteCookie(cookie.slice('redamon-invite='.length).split(';')[0])).toBe(made.linkId)
  })

  test('token not in the redirect target, nor in any header', async () => {
    const made = await openLink()
    const token = tokenOf(made.link)
    const res = await open(token)
    expect(res.headers.get('location')).not.toContain(token)
    for (const [name, value] of res.headers) expect(`${name}: ${value}`).not.toContain(token)
  })

  test('no-referrer header, never cached', async () => {
    const made = await openLink()
    const res = await open(tokenOf(made.link))
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(res.headers.get('cache-control')).toBe('no-store')
  })

  test('opening it does not use it: it can be opened again until accepted', async () => {
    const made = await openLink()
    await open(tokenOf(made.link))
    expect(inviteCookie(await open(tokenOf(made.link)))).toMatch(/Max-Age=1800/i)
    expect(db().invites()[0]).toMatchObject({ usedAt: null, cancelledAt: null })
  })
})

describe('an invalid link', () => {
  test('expired, used, cancelled → the same redirect, the cookie cleared', async () => {
    const expired = await openLink()
    clock = expired.expiresAt
    const tokens = [tokenOf(expired.link)]
    clock = T0
    const used = await openLink()
    await db().userInvite.updateMany({ where: { id: used.linkId }, data: { usedAt: T0 } })
    tokens.push(tokenOf(used.link))
    clock = expired.expiresAt
    for (const token of [...tokens, newLinkToken()]) {
      const res = await open(token)
      expect(res.status).toBe(303)
      expect(res.headers.get('location')).toBe('/invite')
      expect(inviteCookie(res)).toMatch(/Max-Age=0/i)
    }
  })
})

describe('the lookup ceiling', () => {
  test('rate limit after N without a trusted IP: the 31st lookup in a minute answers 429', async () => {
    vi.stubEnv('TRUST_PROXY', '')
    const made = await openLink()
    for (let i = 0; i < 30; i++) {
      const res = await open(newLinkToken(), { 'x-forwarded-for': `10.0.0.${i}` })
      expect(res.status, `lookup ${i + 1}`).toBe(303)
    }
    const res = await open(tokenOf(made.link), { 'x-forwarded-for': '10.0.0.99' })
    expect(res.status).toBe(429)
    expect(res.headers.get('retry-after')).toBe('60')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(inviteCookie(res)).toBeUndefined()
    clock = new Date(T0.getTime() + 60_000)
    expect((await open(tokenOf(made.link))).status).toBe(303)
    vi.unstubAllEnvs()
    vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
  })
})

describe('the switch', () => {
  test('switch off 404, nothing read', async () => {
    const made = await openLink()
    setFlagsForTests({ identity: false })
    const spy = vi.spyOn(db().userInvite, 'findUnique')
    const res = await open(tokenOf(made.link))
    expect(res.status).toBe(404)
    expect(inviteCookie(res)).toBeUndefined()
    expect(spy).not.toHaveBeenCalled()
  })
})
