/**
 * Signing out ends the impersonation (step 3.14; IM-11, AU-03): with RBAC_PERMISSIONS_ENABLED on,
 * the act-as cookie the admin carried gets its end row, `endedBy: 'logout'` (or `expired` when its
 * time had already run out), once; with the switch off the sign-out writes no act-as row, as before.
 *
 * Real route, session helpers and tokens; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  return { default: db, prisma: db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { POST } from './route'

const db = () => h.db as AccountDb
const req = () => new NextRequest('http://redamon.test/api/auth/logout', {
  method: 'POST', headers: { host: 'redamon.test', ...(h.jar.actAs ? { cookie: `redamon-act-as=${h.jar.actAs}` } : {}) },
})
const ends = () => db().actAs().filter((r) => r.event === 'end')

beforeEach(async () => {
  db().reset()
  db().seedUsers([{ id: 'root-1', role: 'admin' }, { id: 'admin-1', role: 'admin' }, { id: 'member-1' }])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  db().seedActAs({ adminId: 'admin-1', targetUserId: 'member-1', event: 'start', createdAt: new Date(Date.now() - 60_000), durationMinutes: 60 })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = { auth: await createToken('admin-1', 'admin', 0), actAs: await createActAsToken('admin-1', 'member-1', 3600, { asv: 0 }) }
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('logout ends the impersonation', () => {
  test('one end row, `logout`, and both cookies expire', async () => {
    const res = await POST(req())
    expect(res.status).toBe(200)
    expect(ends()).toEqual([expect.objectContaining({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'logout' })])
    expect(res.headers.getSetCookie().filter((c) => /Max-Age=0/i.test(c)).length).toBe(2)
    // The sign-out row still names whom the admin was acting as.
    expect(db().audit()).toEqual([expect.objectContaining({ action: 'auth.logout', actorId: 'admin-1', onBehalfOfUserId: 'member-1' })])
  })

  test('its time had run out with no cookie left: `expired`', async () => {
    h.jar.actAs = undefined
    setNowForTests(() => new Date(Date.now() + 2 * 3600_000))
    await POST(req())
    expect(ends()).toEqual([expect.objectContaining({ endedBy: 'expired' })])
  })

  test('switch off: no act-as row, as before', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await POST(req())
    expect(ends()).toEqual([])
  })

  test('a failed end-row write never fails the sign-out (logged)', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(db(), '$transaction').mockRejectedValueOnce(Object.assign(new Error('x'), { code: 'P1001' }))
    const res = await POST(req())
    expect(res.status).toBe(200)
    expect(err.mock.calls.some(([l]) => String(l) === '[rbac] act-as end not recorded at sign-out code=P1001')).toBe(true)
    err.mockRestore()
  })
})
