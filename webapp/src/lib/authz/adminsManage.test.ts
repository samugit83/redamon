/**
 * `admins:manage` widens Phase 2's Root-only gates (step 3.11; PE-08, PE-09, D-02): with the
 * permissions switch on, an admin holding it disables, enables and signs out another admin whose
 * profile sits strictly inside its own admin side, with its own password; a peer with the same
 * profile, a Full admin, a reset and anything on Root stay refused. With the permissions switch off
 * Phase 2's rule answers: another admin is the confirmed Root's.
 *
 * Real routes, session helpers, tokens, bcrypt, step-up and the last-admin guard; the database is
 * the in-memory accountDb; the agent is a fetch double.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/adminsManage.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')
vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')

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

import type { AccountDb } from './__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { getSession } from '@/lib/session'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import { builtinSet, FULL_ADMIN_PROFILE_ID } from './builtinSets'
import { adminTargetGate } from './rootPowers'
import { __resetThrottle } from '@/lib/loginThrottle'
import { POST as disable } from '@/app/api/users/[id]/disable/route'
import { POST as enable } from '@/app/api/users/[id]/enable/route'
import { POST as revoke } from '@/app/api/users/[id]/revoke-sessions/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const ACCOUNTS = [ROOT, 'admin-1', 'admin-m', 'admin-s', 'admin-2', 'member-1']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))
const MANAGER = [...builtinSet(FULL_ADMIN_PROFILE_ID)!.permissions, 'admins:manage']

function req(body: Record<string, unknown> = {}): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x/disable', {
    method: 'POST', headers: { host: 'redamon.test', 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

type Route = typeof disable
async function call(route: Route, actor: string, target: string, body: Record<string, unknown> = {}) {
  await as(actor)
  const res = await route(req(body), params(target))
  return { status: res.status, body: await res.json().catch(() => ({})) as Record<string, unknown> }
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', password: HASH[ROOT] },
    { id: 'admin-1', role: 'admin', password: HASH['admin-1'] },
    { id: 'admin-m', role: 'admin', password: HASH['admin-m'], adminProfileId: 'set-manager' },
    { id: 'admin-s', role: 'admin', password: HASH['admin-s'], adminProfileId: 'set-manager' },
    { id: 'admin-2', role: 'admin', password: HASH['admin-2'] },
    { id: 'member-1', password: HASH['member-1'] },
  ])
  db().seedSet({ id: 'set-manager', kind: 'admin', name: 'Manager', permissions: MANAGER })
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string) => new Response(
    JSON.stringify(String(url).endsWith('/ws/close') ? { closed: 0 } : { stopped: 0 }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
})

describe('an admins:manage holder over a strict subset (permissions switch on)', () => {
  test('disables, enables and signs out a Full admin, with its own password', async () => {
    expect((await call(disable, 'admin-m', 'admin-2')).body.code).toBe('step_up_required')
    expect((await call(disable, 'admin-m', 'admin-2', { stepUpPassword: pw(ROOT) })).body.code).toBe('step_up_failed')
    expect(db().account('admin-2')!.status).toBe('active')
    expect(await call(disable, 'admin-m', 'admin-2', { stepUpPassword: pw('admin-m') })).toMatchObject({ status: 200, body: { status: 'disabled', changed: true } })
    expect(db().account('admin-2')!.status).toBe('disabled')
    expect(await call(enable, 'admin-m', 'admin-2', { stepUpPassword: pw('admin-m') })).toMatchObject({ status: 200, body: { status: 'active', changed: true } })
    const sv = Number(db().account('admin-2')!.sessionVersion)
    expect(await call(revoke, 'admin-m', 'admin-2', { stepUpPassword: pw('admin-m') })).toMatchObject({ status: 200, body: { revoked: true } })
    expect(db().account('admin-2')!.sessionVersion).toBe(sv + 1)
    expect(db().audit().map((a) => [a.action, a.actorId])).toEqual([
      ['user.disable', 'admin-m'], ['user.enable', 'admin-m'], ['user.sessions_revoked', 'admin-m'],
    ])
  })

  test('equal profiles cannot manage each other: 403 not_a_subset before any password', async () => {
    for (const route of [disable, enable, revoke]) {
      expect((await call(route, 'admin-m', 'admin-s', { stepUpPassword: 'wrong' })).body.code).toBe('not_a_subset')
      expect((await call(route, 'admin-s', 'admin-m', { stepUpPassword: 'wrong' })).body.code).toBe('not_a_subset')
    }
    expect(db().audit()).toEqual([])
  })

  test('a Full admin (no admins:manage) still gets Phase 2\'s root_only', async () => {
    for (const route of [disable, enable, revoke]) {
      const r = await call(route, 'admin-1', 'admin-2', { stepUpPassword: pw('admin-1') })
      expect(r).toMatchObject({ status: 403, body: { code: 'root_only', error: 'Only Root can disable, enable or sign out an admin account.' } })
    }
  })

  test('nobody acts on Root, a reset of an admin stays Root\'s', async () => {
    expect((await call(disable, 'admin-m', ROOT, { stepUpPassword: pw('admin-m') })).body.code).toBe('root_protected')
    await as('admin-m')
    const session = (await getSession({ fresh: true }))!
    const reset = await adminTargetGate(req(), session, 'admin-2', pw('admin-m'), 'Only Root can reset another admin\'s credentials.')
    expect(reset instanceof Response && reset.status).toBe(403)
    expect(await (reset as Response).json()).toMatchObject({ code: 'root_only' })
  })

  test('Root keeps its path (Root\'s own password, the Root re-check)', async () => {
    expect((await call(disable, ROOT, 'admin-m', { stepUpPassword: pw('admin-m') })).body.code).toBe('step_up_failed')
    expect(await call(disable, ROOT, 'admin-m', { stepUpPassword: pw(ROOT) })).toMatchObject({ status: 200, body: { status: 'disabled' } })
  })

  test('a member target is unchanged: no admin rule applies', async () => {
    expect(await call(disable, 'admin-m', 'member-1')).toMatchObject({ status: 200, body: { status: 'disabled' } })
  })
})

describe('with the permissions switch off: Phase 2\'s rule', () => {
  test('another admin is the confirmed Root\'s, whatever profile the actor has', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    for (const route of [disable, enable, revoke]) {
      expect((await call(route, 'admin-m', 'admin-2', { stepUpPassword: pw('admin-m') })).body.code).toBe('root_only')
    }
    expect(db().account('admin-2')!.status).toBe('active')
    expect(await call(disable, ROOT, 'admin-2', { stepUpPassword: pw(ROOT) })).toMatchObject({ status: 200 })
  })
})
