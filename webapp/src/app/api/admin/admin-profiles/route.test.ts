/**
 * /api/admin/admin-profiles and /api/admin/admin-profiles/[id] (step 3.11; PE-07, PE-30, ID-21):
 * admin profiles are Root's (`admin_profiles:manage`, with Root's password); Root makes editable
 * copies of the built-ins; a profile holds administration and platform permissions, of the
 * Root-only ones only `admins:manage` (OQ-02); a profile any admin holds is never deleted; a
 * removal signs its admins out; each change commits with its audit row.
 *
 * Real session helpers, tokens, bcrypt, step-up and Root; the database is the in-memory accountDb.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/admin-profiles/route.test.ts
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

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests, loadPrincipal } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests, resolveCapabilities } from '@/lib/authz/capabilities'
import { builtinSet } from '@/lib/authz/builtinSets'
import { __resetThrottle } from '@/lib/loginThrottle'
import { GET, POST } from './route'
import { PUT, DELETE } from './[id]/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const ACCOUNTS = [ROOT, 'admin-1', 'admin-m', 'admin-2', 'member-1']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))
const USER_MANAGER = [...builtinSet('builtin:user-manager')!.permissions]

function req(method: string, body?: unknown, origin?: string): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json' }
  if (origin) headers.origin = origin
  return new NextRequest('http://redamon.test/api/admin/admin-profiles', {
    method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}
type Answer = { status: number; body: Record<string, unknown> }
const answer = async (res: Response): Promise<Answer> => ({ status: res.status, body: await res.json().catch(() => ({})) })
const list = async (actor: string) => { await as(actor); return answer(await GET()) }
const create = async (actor: string, body: Record<string, unknown>, origin?: string) => { await as(actor); return answer(await POST(req('POST', body, origin))) }
const edit = async (actor: string, id: string, body: Record<string, unknown>) => { await as(actor); return answer(await PUT(req('PUT', body), params(id))) }
const remove = async (actor: string, id: string, body: Record<string, unknown> = {}) => { await as(actor); return answer(await DELETE(req('DELETE', body), params(id))) }

function state() {
  return JSON.stringify({ users: ACCOUNTS.map((id) => db().account(id)), sets: db().sets(), audit: db().audit() })
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', password: HASH[ROOT] },
    { id: 'admin-1', role: 'admin', password: HASH['admin-1'] },
    { id: 'admin-m', role: 'admin', password: HASH['admin-m'], adminProfileId: 'set-manager' },
    { id: 'admin-2', role: 'admin', password: HASH['admin-2'], adminProfileId: 'set-desk' },
    { id: 'member-1' },
  ])
  db().seedSet({ id: 'set-manager', kind: 'admin', name: 'Manager', permissions: ['admins:manage', ...USER_MANAGER] })
  db().seedSet({ id: 'set-desk', kind: 'admin', name: 'Help desk', permissions: ['users:read', 'users:edit'] })
  db().seedSet({ id: 'set-empty', kind: 'admin', name: 'Spare', permissions: ['users:read'] })
  db().seedSet({ id: 'set-members', kind: 'member', name: 'Members', permissions: ['graph:read'] })
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 0 }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
})

describe('GET', () => {
  test('Root lists the built-in profiles first, then the stored ones, with their admins', async () => {
    const { status, body } = await list(ROOT)
    expect(status).toBe(200)
    const sets = body.sets as Array<{ id: string; holders: number; kind: string }>
    expect(sets.map((s) => s.id)).toEqual([
      'builtin:full-admin', 'builtin:user-manager', 'builtin:platform-operator', 'builtin:security-auditor',
      'set-desk', 'set-manager', 'set-empty',
    ])
    // Root and admin-1 record no profile: both count for Full admin.
    expect(Object.fromEntries(sets.map((s) => [s.id, s.holders]))).toMatchObject({ 'builtin:full-admin': 2, 'set-desk': 1, 'set-manager': 1, 'set-empty': 0 })
    expect(body).not.toHaveProperty('instanceDefaultSetId')
  })

  test('admins:manage lists them (who gives profiles); a Full admin and a member get 403 admin_profiles:manage', async () => {
    expect((await list('admin-m')).status).toBe(200)
    expect((await list('admin-1')).body).toMatchObject({ code: 'forbidden', permission: 'admin_profiles:manage' })
    expect((await list('member-1')).status).toBe(403)
  })
})

describe('writes are Root\'s, with Root\'s password', () => {
  test('a Full admin and an admins:manage holder get root_only before any password is checked', async () => {
    const before = state()
    for (const actor of ['admin-1', 'admin-m']) {
      expect((await create(actor, { name: 'Mine', permissions: ['users:read'], stepUpPassword: pw(actor) })).body.code).toBe('root_only')
      expect((await edit(actor, 'set-desk', { name: 'Mine', stepUpPassword: pw(actor) })).body.code).toBe('root_only')
      expect((await remove(actor, 'set-empty', { stepUpPassword: pw(actor) })).body.code).toBe('root_only')
    }
    expect(state()).toBe(before)
  })

  test('an unconfirmed Root is told why', async () => {
    db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'automatic' })
    const r = await create(ROOT, { name: 'Mine', permissions: ['users:read'], stepUpPassword: pw(ROOT) })
    expect(r.body.code).toBe('root_only')
    expect(String(r.body.error)).toContain('confirms it')
  })

  test('Root without its password: step_up_required; cross-origin refused', async () => {
    expect((await create(ROOT, { name: 'Mine', permissions: ['users:read'] })).body.code).toBe('step_up_required')
    expect((await create(ROOT, { name: 'Mine', permissions: ['users:read'], stepUpPassword: pw(ROOT) }, 'https://evil.example')).body.code).toBe('cross_origin')
    expect(db().sets().length).toBe(4)
  })
})

describe('POST', () => {
  test('Root makes an editable copy of a built-in profile, with its audit row', async () => {
    const r = await create(ROOT, { name: 'Managers', cloneFrom: 'builtin:user-manager', stepUpPassword: pw(ROOT) })
    expect(r).toMatchObject({ status: 201, body: { set: { kind: 'admin', name: 'Managers', permissions: USER_MANAGER, clonedFrom: 'builtin:user-manager' } } })
    expect(db().audit()).toEqual([expect.objectContaining({ action: 'admin_profile.created', targetType: 'admin_profile', permission: 'admin_profiles:manage', actorId: ROOT })])
  })

  test('admins:manage may go in a custom profile (OQ-02); no other Root-only permission does', async () => {
    expect((await create(ROOT, { name: 'Lead', permissions: ['admins:manage', 'users:read'], stepUpPassword: pw(ROOT) })).status).toBe(201)
    for (const p of ['instance:settings', 'root:transfer', 'admin_profiles:manage', 'projects:administer']) {
      const r = await create(ROOT, { name: `With ${p}`, permissions: ['users:read', p], stepUpPassword: pw(ROOT) })
      expect([p, r.status, r.body.code, r.body.permissions]).toEqual([p, 400, 'root_only_permission', [p]])
    }
  })

  test('a profile holds no member permission; a member set is no profile to clone', async () => {
    expect((await create(ROOT, { name: 'Odd', permissions: ['users:read', 'recon:scan'], stepUpPassword: pw(ROOT) })).body.code).toBe('wrong_kind')
    expect((await create(ROOT, { name: 'Odd', cloneFrom: 'set-members', stepUpPassword: pw(ROOT) })).body.code).toBe('unknown_set')
  })
})

describe('PUT', () => {
  test('a removal signs out the admins holding the profile, and only them', async () => {
    const r = await edit(ROOT, 'set-desk', { permissions: ['users:read'], stepUpPassword: pw(ROOT) })
    expect(r).toMatchObject({ status: 200, body: { removed: ['users:edit'], signedOut: 1, set: { holders: 1 } } })
    expect(db().account('admin-2')!.sessionVersion).toBe(1)
    expect(db().account('admin-m')!.sessionVersion).toBe(0)
    clearPrincipalCacheForTests()
    const caps = await resolveCapabilities((await loadPrincipal('admin-2', { fresh: true }))!, { fresh: true })
    expect(caps.has('users:edit')).toBe(false)
    expect(db().audit().map((a) => a.action)).toEqual(['admin_profile.updated'])
  })

  test('built-in profiles are read-only; a member set is not a profile', async () => {
    expect((await edit(ROOT, 'builtin:full-admin', { name: 'Mine', stepUpPassword: pw(ROOT) })).body.code).toBe('builtin_read_only')
    expect((await edit(ROOT, 'set-members', { name: 'Mine', stepUpPassword: pw(ROOT) })).status).toBe(404)
    expect((await edit(ROOT, 'set-desk', { instanceDefault: true, stepUpPassword: pw(ROOT) })).body.code).toBe('nothing_to_change')
  })
})

describe('DELETE', () => {
  test('a profile an admin holds is refused; an unused one goes with its audit row', async () => {
    expect(await remove(ROOT, 'set-desk', { stepUpPassword: pw(ROOT) })).toMatchObject({ status: 409, body: { code: 'profile_in_use', holders: 1 } })
    expect(await remove(ROOT, 'set-empty', { stepUpPassword: pw(ROOT) })).toMatchObject({ status: 200, body: { deleted: true } })
    expect(db().audit().map((a) => [a.action, a.targetId])).toEqual([['admin_profile.deleted', 'set-empty']])
    expect((await remove(ROOT, 'builtin:security-auditor', { stepUpPassword: pw(ROOT) })).body.code).toBe('builtin_read_only')
  })

  test('audit failure → no change', async () => {
    db().failAudit('admin_profile.deleted')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const before = state()
    expect((await remove(ROOT, 'set-empty', { stepUpPassword: pw(ROOT) })).status).toBe(500)
    err.mockRestore()
    expect(state()).toBe(before)
  })
})
