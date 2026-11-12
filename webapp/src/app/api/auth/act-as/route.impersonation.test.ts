/**
 * POST / DELETE /api/auth/act-as with RBAC_PERMISSIONS_ENABLED on (step 3.14; IM-03, IM-04, IM-09,
 * IM-10, IM-11, ID-25, AU-03): acting as someone needs users:impersonate, an admin acts as members
 * only, an admin target is Root's, nobody acts as Root; a reason (mandatory when Root says so), a
 * duration (default 60 min, held to the instance limit and an admin session), the admin's own
 * password whatever the target; the token expires with the duration and carries the admin's session
 * version; the start row carries reason and duration (no row, no impersonation); the account acted as
 * is told unless Root turned it off; Stop, choosing oneself and a new act-as each end the open one
 * once (`stopped`), an impersonation whose time ran out gets `expired`.
 *
 * Real routes, session helpers, tokens, step-up and capability resolution; the database is the
 * in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'e'.repeat(64))

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
// An ended impersonation closes its agent sockets (actAs.sockets.test.ts): no agent here.
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async () => ({ ok: true, closed: 0, stoppedRuns: 0 })) }))

import bcrypt from 'bcryptjs'
import { decodeJwt } from 'jose'
import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createActAsToken, createToken } from '@/lib/auth'
import { __resetThrottle } from '@/lib/loginThrottle'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { readNotices } from '@/lib/authz/accountNotices'
import { POST, DELETE } from './route'

const db = () => h.db as AccountDb
const PW: Record<string, string> = {
  'root-1': 'root-one-passphrase',
  'admin-1': 'admin-one-passphrase',
  'admin-um': 'user-manager-passphrase',
}

function req(method: 'POST' | 'DELETE', body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/auth/act-as', {
    method,
    headers: {
      host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json',
      ...(h.jar.actAs ? { cookie: `redamon-act-as=${h.jar.actAs}` } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}

async function signIn(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
  h.jar.actAs = undefined
}

/** POST as the signed-in admin; on success the browser keeps the cookie. */
async function actAs(body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown>; cookie: string | null }> {
  const res = await POST(req('POST', body))
  const line = res.headers.getSetCookie().find((c) => c.startsWith('redamon-act-as=')) ?? null
  const value = line ? line.slice('redamon-act-as='.length).split(';')[0] : null
  if (res.status === 200) h.jar.actAs = value || undefined
  return { status: res.status, body: await res.json() as Record<string, unknown>, cookie: line }
}

const starts = () => db().actAs().filter((r) => r.event === 'start')
const ends = () => db().actAs().filter((r) => r.event === 'end')

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin', password: bcrypt.hashSync(PW['root-1'], 4), name: 'Rita' },
    { id: 'admin-1', role: 'admin', password: bcrypt.hashSync(PW['admin-1'], 4), name: 'Laura', sessionVersion: 3 },
    { id: 'admin-2', role: 'admin' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager', password: bcrypt.hashSync(PW['admin-um'], 4) },
    { id: 'member-1', name: 'Marco' },
    { id: 'member-2' },
    { id: 'member-off', status: 'disabled' },
  ])
  db().seedInstance({
    rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z'),
    impersonationMaxMinutes: 720, impersonationReasonRequired: false, impersonationNotifyTarget: true, adminSessionTtlHours: 12,
  })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('targets (IM-03)', () => {
  test('member: an admin holding users:impersonate acts as a member', async () => {
    await signIn('admin-1')
    const r = await actAs({ targetUserId: 'member-1', reason: 'ticket #42', stepUpPassword: PW['admin-1'] })
    expect(r.status).toBe(200)
    expect(r.body).toMatchObject({ actingAs: 'member-1', durationMinutes: 60, endsAt: expect.any(String) })
    expect(r.cookie).toMatch(/HttpOnly/i)
  })

  test('admin by admin: refused, Root only, before any password is checked', async () => {
    await signIn('admin-1')
    const r = await actAs({ targetUserId: 'admin-2', reason: 'x', stepUpPassword: 'wrong' })
    expect(r.status).toBe(403)
    expect(r.body).toMatchObject({ code: 'root_only' })
    expect(starts()).toEqual([])
  })

  test('admin by Root: allowed with Root\'s own password', async () => {
    await signIn('root-1')
    const r = await actAs({ targetUserId: 'admin-2', reason: 'audit', stepUpPassword: PW['root-1'] })
    expect(r.status).toBe(200)
    expect(starts()).toEqual([expect.objectContaining({ adminId: 'root-1', targetUserId: 'admin-2', reason: 'audit' })])
  })

  test('Root: nobody acts as Root', async () => {
    await signIn('admin-1')
    const r = await actAs({ targetUserId: 'root-1', reason: 'x', stepUpPassword: PW['admin-1'] })
    expect(r.status).toBe(403)
    expect(r.body).toMatchObject({ code: 'root_protected' })
    expect(r.cookie).toBeNull()
  })

  test('a profile without users:impersonate (User manager) is refused naming it, before the body', async () => {
    await signIn('admin-um')
    const r = await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: PW['admin-um'] })
    expect(r.status).toBe(403)
    expect(r.body).toEqual({ error: expect.any(String), code: 'forbidden', permission: 'users:impersonate' })
  })

  test('a disabled account is acted as by nobody', async () => {
    await signIn('admin-1')
    const r = await actAs({ targetUserId: 'member-off', reason: 'x', stepUpPassword: PW['admin-1'] })
    expect(r.status).toBe(409)
    expect(r.body).toMatchObject({ code: 'account_disabled' })
  })

  test('step-up always: a member target needs the admin\'s own password too (ID-25)', async () => {
    await signIn('admin-1')
    expect((await actAs({ targetUserId: 'member-1', reason: 'x' })).body).toMatchObject({ code: 'step_up_required' })
    expect((await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: 'nope' })).body).toMatchObject({ code: 'step_up_failed' })
    expect(starts()).toEqual([])
  })
})

describe('reason and duration (IM-04)', () => {
  test('reason required when set: refused before the password is spent', async () => {
    db().seedInstance({ ...db().instance(), impersonationReasonRequired: true })
    await signIn('admin-1')
    const r = await actAs({ targetUserId: 'member-1', stepUpPassword: 'wrong' })
    expect(r.status).toBe(400)
    expect(r.body).toMatchObject({ code: 'reason_required', field: 'reason' })
    // The wrong password was never checked: the right one still passes at once.
    expect((await actAs({ targetUserId: 'member-1', reason: 'ticket #42', stepUpPassword: PW['admin-1'] })).status).toBe(200)
  })

  test('not required: an empty reason is recorded as none', async () => {
    await signIn('admin-1')
    expect((await actAs({ targetUserId: 'member-1', stepUpPassword: PW['admin-1'] })).status).toBe(200)
    expect(starts()[0].reason).toBeNull()
  })

  const lifetime = (cookie: string | null) => {
    const token = cookie!.slice('redamon-act-as='.length).split(';')[0]
    const c = decodeJwt(token)
    return { seconds: c.exp! - c.iat!, maxAge: Number(/Max-Age=(\d+)/i.exec(cookie!)?.[1]), asv: c.asv }
  }

  test('cookie expiry = duration: token and cookie live the chosen minutes', async () => {
    await signIn('admin-1')
    const r = await actAs({ targetUserId: 'member-1', reason: 'x', durationMinutes: 45, stepUpPassword: PW['admin-1'] })
    expect(lifetime(r.cookie)).toEqual({ seconds: 45 * 60, maxAge: 45 * 60, asv: 3 })
    expect(r.body).toMatchObject({ durationMinutes: 45 })
    expect(Date.parse(r.body.endsAt as string)).toBe(decodeJwt(h.jar.actAs!).exp! * 1000)
  })

  test('duration capped: at the instance limit, at 720 whatever is stored, and at an admin session', async () => {
    await signIn('admin-1')
    expect(lifetime((await actAs({ targetUserId: 'member-1', reason: 'x', durationMinutes: 721, stepUpPassword: PW['admin-1'] })).cookie).seconds)
      .toBe(720 * 60)
    db().seedInstance({ ...db().instance(), impersonationMaxMinutes: 30 })
    expect(lifetime((await actAs({ targetUserId: 'member-1', reason: 'x', durationMinutes: 90, stepUpPassword: PW['admin-1'] })).cookie).seconds)
      .toBe(30 * 60)
    db().seedInstance({ ...db().instance(), impersonationMaxMinutes: 1440, adminSessionTtlHours: 2 })
    const r = await actAs({ targetUserId: 'member-1', reason: 'x', durationMinutes: 600, stepUpPassword: PW['admin-1'] })
    expect(lifetime(r.cookie).seconds).toBe(120 * 60)
    expect(starts().at(-1)).toMatchObject({ durationMinutes: 120 })
  })

  test('default 60 minutes', async () => {
    await signIn('admin-1')
    expect(lifetime((await actAs({ targetUserId: 'member-1', stepUpPassword: PW['admin-1'] })).cookie).seconds).toBe(3600)
  })

  test('a bad duration is a 400 naming the field', async () => {
    await signIn('admin-1')
    const r = await actAs({ targetUserId: 'member-1', durationMinutes: 0, stepUpPassword: PW['admin-1'] })
    expect(r.status).toBe(400)
    expect(r.body).toMatchObject({ code: 'invalid_field', field: 'durationMinutes' })
  })
})

describe('audit rows and the notice (IM-09, IM-10, AU-03)', () => {
  test('the start row carries reason and duration; the real admin is its admin', async () => {
    await signIn('admin-1')
    await actAs({ targetUserId: 'member-1', reason: 'ticket #42', durationMinutes: 35, stepUpPassword: PW['admin-1'] })
    expect(starts()).toEqual([expect.objectContaining({
      adminId: 'admin-1', targetUserId: 'member-1', event: 'start', reason: 'ticket #42', durationMinutes: 35, source: 'api',
    })])
  })

  test('no start row, no impersonation: a failed write answers 500 and sets no cookie', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    vi.spyOn(db().actAsAudit, 'create').mockRejectedValueOnce(Object.assign(new Error('gone'), { code: 'P1001' }))
    const r = await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: PW['admin-1'] })
    expect(r.status).toBe(500)
    expect(r.body).toEqual({ error: 'Could not switch user', code: 'P1001' })
    expect(r.cookie).toBeNull()
  })

  test('target notice: the account acted as is told who, why and for how long', async () => {
    await signIn('admin-1')
    await actAs({ targetUserId: 'member-1', reason: 'ticket #42', durationMinutes: 35, stepUpPassword: PW['admin-1'] })
    expect(readNotices(db().account('member-1')!.pendingNotices)).toEqual([expect.objectContaining({
      type: 'acted_as', by: { id: 'admin-1', name: 'Laura', email: 'admin-1@e2e.local' }, reason: 'ticket #42', durationMinutes: 35,
    })])
  })

  test('no notice when Root turned it off', async () => {
    db().seedInstance({ ...db().instance(), impersonationNotifyTarget: false })
    await signIn('admin-1')
    await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: PW['admin-1'] })
    expect(db().account('member-1')!.pendingNotices).toEqual([])
  })

  test('a notice that cannot be written does not stop the impersonation (logged)', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    const original = db().$executeRaw
    vi.spyOn(db(), '$executeRaw').mockImplementation(async (strings: TemplateStringsArray, ...values: unknown[]) => {
      if (strings.join('?').includes('pending_notices')) throw Object.assign(new Error('x'), { code: 'P2024' })
      return original(strings, ...values)
    })
    const r = await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: PW['admin-1'] })
    expect(r.status).toBe(200)
    expect(err.mock.calls.some(([line]) => String(line).startsWith('[rbac] act-as notice not written target=member-1 code=P2024'))).toBe(true)
  })
})

describe('ends with endedBy (IM-11)', () => {
  test('Stop (DELETE) ends it once with `stopped` and clears the cookie', async () => {
    await signIn('admin-1')
    await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: PW['admin-1'] })
    const res = await DELETE(req('DELETE'))
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
    await DELETE(req('DELETE'))
    expect(ends()).toEqual([expect.objectContaining({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'stopped' })])
  })

  test('choosing oneself ends it with `stopped`', async () => {
    await signIn('admin-1')
    await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: PW['admin-1'] })
    expect((await actAs({ targetUserId: 'admin-1' })).body).toEqual({ actingAs: null })
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'stopped' })])
  })

  test('acting as someone else ends the open one first', async () => {
    await signIn('admin-1')
    await actAs({ targetUserId: 'member-1', reason: 'x', stepUpPassword: PW['admin-1'] })
    await actAs({ targetUserId: 'member-2', reason: 'y', stepUpPassword: PW['admin-1'] })
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'stopped' })])
    expect(starts().map((r) => r.targetUserId)).toEqual(['member-1', 'member-2'])
  })

  test('expiry: a Stop after the time ran out (the browser dropped the cookie) records `expired`', async () => {
    db().seedActAs({ adminId: 'admin-1', targetUserId: 'member-1', event: 'start', createdAt: new Date('2026-11-12T09:00:00Z'), durationMinutes: 30 })
    setNowForTests(() => new Date('2026-11-12T09:31:00Z'))
    await signIn('admin-1')
    await DELETE(req('DELETE'))
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'expired' })])
  })

  test("another admin's cookie ends nothing", async () => {
    await signIn('admin-1')
    h.jar.actAs = await createActAsToken('root-1', 'member-1', 600, { asv: 0 })
    await DELETE(req('DELETE'))
    expect(ends()).toEqual([])
  })
})
