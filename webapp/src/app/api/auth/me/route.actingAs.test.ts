/**
 * GET /api/auth/me says whom an admin is acting as (step 3.14; IM-02, IM-05, ID-31): with
 * RBAC_PERMISSIONS_ENABLED on, administrator accounts get `actingAs` (the account's name, email and
 * type, the reason, when it ends: the banner and the switcher read it, the browser no longer keeps
 * it) and `impersonation` (the instance limit and whether a reason is required: the dialog offers
 * them). Null when not acting. Members get neither; with the switch off the answer has neither key.
 * The top-level fields stay the real person's.
 *
 * Real route, session helpers and tokens; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: (name: string) => { if (name === 'redamon-act-as') h.jar.actAs = undefined },
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  return { default: db, prisma: db }
})
vi.mock('@/lib/authz/updateReview', () => ({ pendingLegacyGrantCount: async () => 0 }))

import { decodeJwt } from 'jose'
import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { GET } from './route'

const db = () => h.db as AccountDb

async function signIn(userId: string, actingAs?: string) {
  h.jar.auth = await createToken(userId, String(db().account(userId)!.role), 0)
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs, 2400, { asv: 0 }) : undefined
}
const me = async () => (await GET()).json() as Promise<Record<string, unknown>>

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin', name: 'Rita' },
    { id: 'admin-1', role: 'admin', name: 'Laura' },
    { id: 'member-1', name: 'Marco' },
  ])
  db().seedInstance({
    rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z'),
    impersonationMaxMinutes: 240, impersonationReasonRequired: true, impersonationNotifyTarget: true,
  })
  db().seedActAs({ adminId: 'admin-1', targetUserId: 'member-1', event: 'start', createdAt: new Date(), reason: 'ticket #42', durationMinutes: 40 })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
})
afterEach(() => setFlagsForTests(null))

describe('banner content: whom, why, until when', () => {
  test('an admin acting as a member: the member named by name, email and type, the reason, the end', async () => {
    await signIn('admin-1', 'member-1')
    const body = await me()
    expect(body.id).toBe('admin-1')
    expect(body.actingAs).toEqual({
      id: 'member-1', name: 'Marco', email: 'member-1@e2e.local', accountType: 'member', reason: 'ticket #42',
      endsAt: new Date(decodeJwt(h.jar.actAs!).exp! * 1000).toISOString(),
    })
    expect(body.impersonation).toEqual({ maxMinutes: 240, reasonRequired: true })
  })

  test('Root acting as an admin: the type says admin', async () => {
    db().seedActAs({ adminId: 'root-1', targetUserId: 'admin-1', event: 'start', createdAt: new Date(), reason: null, durationMinutes: 60 })
    await signIn('root-1', 'admin-1')
    expect((await me()).actingAs).toMatchObject({ id: 'admin-1', accountType: 'admin', reason: null })
  })

  test('not acting: actingAs null, the limits still there for the dialog', async () => {
    await signIn('admin-1')
    const body = await me()
    expect(body.actingAs).toBeNull()
    expect(body.impersonation).toEqual({ maxMinutes: 240, reasonRequired: true })
  })

  test('an impersonation that ended on this request (account disabled) is not shown', async () => {
    await db().user.update({ where: { id: 'member-1' }, data: { status: 'disabled' } })
    await signIn('admin-1', 'member-1')
    expect((await me()).actingAs).toBeNull()
  })

  test('members get neither key', async () => {
    await signIn('member-1')
    const body = await me()
    expect('actingAs' in body).toBe(false)
    expect('impersonation' in body).toBe(false)
  })

  test('switch off: neither key, for anyone', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await signIn('admin-1', 'member-1')
    const body = await me()
    expect('actingAs' in body).toBe(false)
    expect('impersonation' in body).toBe(false)
  })

  test('an unreadable act-as log leaves actingAs null and the session answering (logged)', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1', 'member-1')
    vi.spyOn(db().actAsAudit, 'findFirst').mockRejectedValueOnce(Object.assign(new Error('x'), { code: 'P1001' }))
    const res = await GET()
    expect(res.status).toBe(200)
    expect((await res.json()).actingAs).toBeNull()
    expect(err.mock.calls.some(([l]) => String(l) === '[rbac] could not read the act-as session: P1001')).toBe(true)
    err.mockRestore()
  })
})
