/**
 * GET /api/auth/me tells an admin, and only an admin, what the header's banners show
 * (HD-30, HD-29, step 1.18): `rbac.compat` while REDAMON_SHARED_TOOLS_COMPAT is on, and
 * how many legacy grants still wait for a decision. A member's answer is unchanged. The
 * extra read never fails the session: the whole app reads it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createFakePrisma } = await import('@/lib/plugins/__testing__/fakePrisma')
  h.db = createFakePrisma()
  return { default: h.db, prisma: h.db }
})

import type { FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { KEEP_ACTION } from '@/lib/authz/updateReview'
import { GET } from './route'

const db = () => h.db as FakePrisma
const T = new Date('2026-01-01T00:00:00.000Z')

beforeEach(() => {
  for (const t of Object.values(db().tables)) t.clear()
  db().seed('user', [
    { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', password: 'h', createdAt: T, updatedAt: T, legacyGrants: [] },
    { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', role: 'standard', password: 'h', createdAt: T, updatedAt: T,
      legacyGrants: ['kali_terminal', 'shell_sessions'] },
  ])
  db().seed('auditLog', [{ action: KEEP_ACTION, targetType: 'user', targetId: 'member-1', actorId: 'admin-1', after: { grant: 'shell_sessions' } }])
  setFlagsForTests({ sharedToolsCompat: false })
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('GET /api/auth/me', () => {
  test('a member gets its account and no rbac block, whatever the switch', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    h.jar.auth = await createToken('member-1', 'standard')
    const res = await GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'member-1', name: 'Marco', email: 'marco@e2e.local', role: 'standard' })
  })

  test('an admin gets rbac.compat false and the pending count while the switch is off', async () => {
    h.jar.auth = await createToken('admin-1', 'admin')
    expect(await (await GET()).json()).toEqual({
      id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin',
      rbac: { compat: false, legacyGrantsPending: 1 },
    })
  })

  test('banner only while compat is on: rbac.compat true with the switch on', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    h.jar.auth = await createToken('admin-1', 'admin')
    expect((await (await GET()).json()).rbac).toEqual({ compat: true, legacyGrantsPending: 1 })
  })

  test('identity: true only while the identity switch is on (step 2.3); a member never gets it', async () => {
    setFlagsForTests({ identity: true })
    h.jar.auth = await createToken('admin-1', 'admin')
    expect((await (await GET()).json()).rbac).toEqual({ compat: false, legacyGrantsPending: 1, identity: true })
    h.jar.auth = await createToken('member-1', 'standard')
    expect(await (await GET()).json()).not.toHaveProperty('rbac')
  })

  test('a demoted admin (token still says admin) is a member here', async () => {
    h.jar.auth = await createToken('member-1', 'admin')
    expect(await (await GET()).json()).not.toHaveProperty('rbac')
  })

  test('a failed pending read answers the account with legacyGrantsPending null and logs it', async () => {
    h.jar.auth = await createToken('admin-1', 'admin')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(db().auditLog, 'findMany').mockRejectedValueOnce(Object.assign(new Error('boom'), { code: 'P1001' }))
    const res = await GET()
    expect(res.status).toBe(200)
    expect((await res.json()).rbac).toEqual({ compat: false, legacyGrantsPending: null })
    expect(String(err.mock.calls[0]?.[0])).toMatch(/^\[rbac\] could not read the legacy grant review: P1001/)
  })

  test('no session 401', async () => {
    expect((await GET()).status).toBe(401)
  })

  // Step 2.2 review: getSession clears a refused cookie only with the identity switch on, and
  // only then does this answer send the browser to sign-in (AuthProvider).
  test('with the identity switch on a refused cookie answers 401 session_ended', async () => {
    setFlagsForTests({ identity: true })
    h.jar.auth = await createToken('gone', 'standard')
    const res = await GET()
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Unauthorized', code: 'session_ended' })
  })

  test("with the switch off a refused cookie gets Phase 1's bare 401", async () => {
    h.jar.auth = await createToken('member-1', 'standard', 1)
    const res = await GET()
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Unauthorized' })
  })
})
