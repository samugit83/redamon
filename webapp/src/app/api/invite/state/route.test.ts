/**
 * GET /api/invite/state (step 2.9, ID-15, ID-20), public: what the `/invite` page shows, read from
 * the invite cookie. A valid link answers the account's name and address, the link's kind and
 * expiry, and the password policy in force (the page has no session, so the policy comes with
 * the link, never from the session-only /api/auth/password-policy); anything else answers only
 * `{valid: false}`. Never cached, no referrer. With the identity switch off: 404.
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
import { createLink, signInviteCookie } from '@/lib/authz/invites'
import { GET } from './route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')

const state = (cookie?: string) => GET(new NextRequest('http://redamon.test/api/invite/state', {
  headers: cookie ? { cookie } : {},
}))

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin' },
    { id: 'invited-1', name: 'Nina', status: 'invited', password: '', email: 'nina@e2e.local' },
  ])
  db().seedInstance({ inviteTtlHours: 168, passwordMinLength: 16 })
  setFlagsForTests({ identity: true })
  setNowForTests(() => T0)
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('GET /api/invite/state', () => {
  test('a valid link: who it is for, its expiry, and the policy in force', async () => {
    const made = await db().$transaction((tx) => createLink(tx as never, { userId: 'invited-1', kind: 'invite', createdById: 'admin-1' }))
    const res = await state(`redamon-invite=${await signInviteCookie(made.linkId)}`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(await res.json()).toEqual({
      valid: true,
      kind: 'invite',
      name: 'Nina',
      email: 'nina@e2e.local',
      expiresAt: made.expiresAt.toISOString(),
      policy: {
        minLength: 16,
        maxBytes: 72,
        rules: true,
        description: 'At least 16 characters and at most 72 bytes; not a common password, not your email address or its name part, not one character repeated.',
      },
    })
  })

  test('/api/invite/state is public: no cookie at all answers {valid: false}, never 401', async () => {
    const res = await state()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ valid: false })
  })

  test('used, cancelled or tampered: only {valid: false}, nothing about the account', async () => {
    const made = await db().$transaction((tx) => createLink(tx as never, { userId: 'invited-1', kind: 'invite', createdById: 'admin-1' }))
    const value = await signInviteCookie(made.linkId)
    await db().userInvite.updateMany({ where: { id: made.linkId }, data: { usedAt: T0 } })
    for (const cookie of [`redamon-invite=${value}`, `redamon-invite=${value.slice(0, -2)}xx`]) {
      const res = await state(cookie)
      const text = await res.text()
      expect(JSON.parse(text)).toEqual({ valid: false })
      expect(text).not.toContain('nina')
    }
  })

  test('switch off 404', async () => {
    setFlagsForTests({ identity: false })
    expect((await state()).status).toBe(404)
  })
})
