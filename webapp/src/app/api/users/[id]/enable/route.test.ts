/**
 * POST /api/users/[id]/enable (step 2.3, ID-13, UP-05): an admin enables a disabled account.
 * The held password comes back (a password set while it was disabled stays), the status is
 * `active`, and `user.enable` is written in the same transaction. Open whatever the identity
 * switch, so an account disabled while it was on can always be restored: with the switch on
 * an admin target needs Root (`root_only`); off, another admin needs step-up (Phase 1 rule).
 *
 * Real session helpers, tokens and step-up; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

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
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearAttempts } from '@/lib/loginThrottle'
import { stepUpThrottleKey } from '@/lib/authz/stepUp'
import { POST } from './route'

const db = () => h.db as AccountDb
const HELD = '$2a$12$held-hash-of-member-1'
const ADMIN_PASSWORD = 'admin-one-passphrase'
let adminHash = ''

function req(body: unknown = {}, opts: { origin?: string; contentType?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.origin !== undefined) headers.origin = opts.origin
  return new NextRequest('http://redamon.test/api/users/x/enable', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })
async function signIn(userId: string, role = 'admin') {
  h.jar.auth = await createToken(userId, role, Number(db().account(userId)?.sessionVersion ?? 0))
}

beforeEach(async () => {
  adminHash ||= await bcrypt.hash(ADMIN_PASSWORD, 4)
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin', password: adminHash },
    { id: 'admin-2', role: 'admin', status: 'disabled', password: '', passwordOnHold: '$2a$12$held-hash-of-admin-2', sessionVersion: 1 },
    { id: 'member-1', status: 'disabled', password: '', passwordOnHold: HELD, sessionVersion: 1 },
    { id: 'member-2' },
  ])
  db().seedToken({ id: 'tok-1', userId: 'member-1', revokedAt: new Date('2026-02-01T00:00:00Z') })
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  clearAttempts(stepUpThrottleKey('admin-1'), null)
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('enable a disabled member', () => {
  test('restores the password', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'member-1', status: 'active', changed: true })
    expect(db().account('member-1')).toMatchObject({ status: 'active', password: HELD, passwordOnHold: '', sessionVersion: 1 })
    expect(db().audit()).toEqual([expect.objectContaining({
      actorId: 'admin-1', action: 'user.enable', targetType: 'user', targetId: 'member-1',
      before: { status: 'disabled' }, after: { status: 'active', passwordRestored: true },
    })])
    expect(JSON.stringify(db().audit())).not.toContain('$2a$')
  })

  test('the MCP tokens revoked at the disable stay revoked', async () => {
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    expect(db().tokens()[0].revokedAt).toEqual(new Date('2026-02-01T00:00:00Z'))
  })

  test('a password set while it was disabled stays; the held one is dropped', async () => {
    db().seedUsers([{ id: 'member-3', status: 'disabled', password: '$2a$12$set-while-disabled', passwordOnHold: '$2a$12$old' }])
    await signIn('admin-1')
    await POST(req(), params('member-3'))
    expect(db().account('member-3')).toMatchObject({ status: 'active', password: '$2a$12$set-while-disabled', passwordOnHold: '' })
    expect(db().audit()[0].after).toEqual({ status: 'active', passwordRestored: false })
  })

  test('an active account: nothing changes, no row', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('member-2'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'member-2', status: 'active', changed: false })
    expect(db().audit()).toEqual([])
  })

  test('the same enable twice: the second changes nothing', async () => {
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    expect((await (await POST(req(), params('member-1'))).json()).changed).toBe(false)
    expect(db().account('member-1')!.password).toBe(HELD)
    expect(db().audit()).toHaveLength(1)
  })

  test('an account in another state (invited) is not made active: 409 not_disabled', async () => {
    db().seedUsers([{ id: 'invited-1', status: 'invited', password: '' }])
    await signIn('admin-1')
    const res = await POST(req(), params('invited-1'))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('not_disabled')
    expect(db().account('invited-1')!.status).toBe('invited')
  })

  test('audit failure → still disabled', async () => {
    db().failAudit('user.enable')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    expect((await POST(req(), params('member-1'))).status).toBe(500)
    expect(db().account('member-1')).toMatchObject({ status: 'disabled', password: '', passwordOnHold: HELD })
  })
})

describe('who may enable', () => {
  test('available with the switch off', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(200)
    expect(db().account('member-1')).toMatchObject({ status: 'active', password: HELD })
  })

  test('switch on: an admin target needs Root (403 root_only)', async () => {
    await signIn('admin-1')
    const res = await POST(req({ stepUpPassword: ADMIN_PASSWORD }), params('admin-2'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_only')
    expect(db().account('admin-2')!.status).toBe('disabled')
  })

  test('switch off: another admin needs the acting admin\'s own password', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    const missing = await POST(req(), params('admin-2'))
    expect(missing.status).toBe(403)
    expect((await missing.json()).code).toBe('step_up_required')
    const wrong = await POST(req({ stepUpPassword: 'not-it' }), params('admin-2'))
    expect((await wrong.json()).code).toBe('step_up_failed')
    expect(db().account('admin-2')!.status).toBe('disabled')
    const ok = await POST(req({ stepUpPassword: ADMIN_PASSWORD }), params('admin-2'))
    expect(ok.status).toBe(200)
    expect(db().account('admin-2')).toMatchObject({ status: 'active', password: '$2a$12$held-hash-of-admin-2' })
  })

  test('a member 403, coded with the permission', async () => {
    await signIn('member-2', 'standard')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:disable' })
    expect(db().account('member-1')!.status).toBe('disabled')
  })

  test('no session 401', async () => {
    expect((await POST(req(), params('member-1'))).status).toBe(401)
  })

  test('cross-origin refused', async () => {
    await signIn('admin-1')
    const res = await POST(req({}, { origin: 'https://evil.example' }), params('member-1'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
    expect(db().account('member-1')!.status).toBe('disabled')
  })

  test('a body that is not JSON 415', async () => {
    await signIn('admin-1')
    expect((await POST(req('x', { contentType: 'text/plain' }), params('member-1'))).status).toBe(415)
    expect(db().account('member-1')!.status).toBe('disabled')
  })

  test('unknown account 404', async () => {
    await signIn('admin-1')
    expect((await (await POST(req(), params('nobody'))).json()).code).toBe('user_not_found')
  })
})
