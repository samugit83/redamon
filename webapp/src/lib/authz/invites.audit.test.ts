/**
 * ID-16 (step 2.9): the invite flow's audit rows. `user.invite`, `user.invite_resent` and
 * `user.invite_cancelled` name the admin who acted (the real person, `auditActor`); the person
 * who accepts writes `user.invite_accepted` as themselves; a link cancelled after five failed
 * accepts writes `user.invite_locked` with no actor. Every row targets the account, carries
 * what changed and no token, hash or password.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearPrincipalCacheForTests } from './principal'
import { resetInviteLimitsForTests } from './inviteLimits'
import { signInviteCookie } from './invites'
import { POST as invite } from '@/app/api/users/invite/route'
import { POST as resend } from '@/app/api/users/[id]/invite/resend/route'
import { POST as cancel } from '@/app/api/users/[id]/invite/cancel/route'
import { POST as accept } from '@/app/api/invite/accept/route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')
const EXPIRES = new Date(T0.getTime() + 168 * 3600_000).toISOString()

function post(body: unknown, cookie?: string): NextRequest {
  return new NextRequest('http://redamon.test/api/x', {
    method: 'POST',
    headers: { host: 'redamon.test', 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const openLinkId = (userId: string) => db().invites().find((r) => r.userId === userId && !r.cancelledAt && !r.usedAt)!.id as string

beforeEach(async () => {
  db().reset()
  db().seedUsers([{ id: 'admin-1', role: 'admin', email: 'ada@e2e.local' }])
  db().seedInstance({ inviteTtlHours: 168 })
  setFlagsForTests({ identity: true })
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  resetInviteLimitsForTests()
  h.jar = { auth: await createToken('admin-1', 'admin') }
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('the invite audit rows', () => {
  test('user.invite, user.invite_resent, user.invite_accepted, user.invite_cancelled, user.invite_locked', async () => {
    const nina = await (await invite(post({ name: 'Nina', email: 'nina@e2e.local' }))).json()
    await resend(post({}), params(nina.id))
    const omar = await (await invite(post({ name: 'Omar', email: 'omar@e2e.local' }))).json()
    await cancel(post({}), params(omar.id))
    const pia = await (await invite(post({ name: 'Pia', email: 'pia@e2e.local' }))).json()

    h.jar = {}
    const ninaCookie = `redamon-invite=${await signInviteCookie(openLinkId(nina.id))}`
    expect((await accept(post({ password: 'violet-harbour-lantern-42' }, ninaCookie))).status).toBe(200)
    const piaCookie = `redamon-invite=${await signInviteCookie(openLinkId(pia.id))}`
    for (let i = 0; i < 5; i++) await accept(post({ password: 'short' }, piaCookie))

    const rows = db().audit().map(({ actorId, actorEmail, action, targetType, targetId, before, after, source }) => (
      { actorId, actorEmail, action, targetType, targetId, before, after, source }
    ))
    const admin = { actorId: 'admin-1', actorEmail: 'ada@e2e.local', targetType: 'user', source: 'api' }
    expect(rows).toEqual([
      { ...admin, action: 'user.invite', targetId: nina.id, before: undefined, after: { email: 'nina@e2e.local', role: 'standard', status: 'invited', expiresAt: EXPIRES } },
      { ...admin, action: 'user.invite_resent', targetId: nina.id, before: undefined, after: { expiresAt: EXPIRES, cancelledLinks: 1 } },
      { ...admin, action: 'user.invite', targetId: omar.id, before: undefined, after: { email: 'omar@e2e.local', role: 'standard', status: 'invited', expiresAt: EXPIRES } },
      { ...admin, action: 'user.invite_cancelled', targetId: omar.id, before: { email: 'omar@e2e.local', status: 'invited' }, after: undefined },
      { ...admin, action: 'user.invite', targetId: pia.id, before: undefined, after: { email: 'pia@e2e.local', role: 'standard', status: 'invited', expiresAt: EXPIRES } },
      { actorId: nina.id, actorEmail: 'nina@e2e.local', targetType: 'user', source: 'api', action: 'user.invite_accepted', targetId: nina.id, before: undefined, after: { kind: 'invite' } },
      { actorId: null, actorEmail: undefined, targetType: 'user', source: 'api', action: 'user.invite_locked', targetId: pia.id, before: undefined, after: { kind: 'invite', failedAccepts: 5 } },
    ])
  })
})
