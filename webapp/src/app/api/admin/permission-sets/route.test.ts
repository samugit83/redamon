/**
 * /api/admin/permission-sets and /api/admin/permission-sets/[id] (step 3.11; PE-07, PE-11, PE-17,
 * ID-21, ID-25): listing, creating, cloning, editing and deleting member permission sets, and the
 * instance's default set. An edit adds only what the editor holds; a set anyone holds, or the
 * default, is never deleted; a removal signs the holders out; every change commits with its audit
 * row.
 *
 * Real session helpers, tokens, bcrypt, step-up, resolution; the database is the in-memory
 * accountDb (transactions roll back); the agent is a fetch double.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/permission-sets/route.test.ts
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
const ACCOUNTS = [ROOT, 'admin-1', 'admin-u', 'admin-p', 'admin-r', 'member-1', 'member-2', 'member-3']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))
const RECON = [...builtinSet('builtin:recon-operator')!.permissions]
const READ_ONLY = [...builtinSet('builtin:read-only-analyst')!.permissions]

function req(method: string, body?: unknown, origin?: string): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json' }
  if (origin) headers.origin = origin
  return new NextRequest('http://redamon.test/api/admin/permission-sets', {
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
const remove = async (actor: string, id: string, origin?: string) => { await as(actor); return answer(await DELETE(req('DELETE', undefined, origin), params(id))) }

function state() {
  return JSON.stringify({ users: ACCOUNTS.map((id) => db().account(id)), sets: db().sets(), assignments: db().assignments(), instance: db().instance(), audit: db().audit() })
}

async function held(userId: string): Promise<readonly string[]> {
  clearPrincipalCacheForTests()
  return (await resolveCapabilities((await loadPrincipal(userId, { fresh: true }))!, { fresh: true })).held
}
const wsClosedFor = () => fetchMock.mock.calls
  .filter(([url]) => String(url).endsWith('/ws/close'))
  .map(([, init]) => JSON.parse(String(init.body)).user_id)

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', password: HASH[ROOT] },
    { id: 'admin-1', role: 'admin', password: HASH['admin-1'] },
    { id: 'admin-u', role: 'admin', password: HASH['admin-u'], adminProfileId: 'builtin:user-manager' },
    { id: 'admin-p', role: 'admin', password: HASH['admin-p'], adminProfileId: 'builtin:platform-operator' },
    { id: 'admin-r', role: 'admin', password: HASH['admin-r'] },
    { id: 'member-1' }, { id: 'member-2' }, { id: 'member-3' },
  ])
  db().seedSet({ id: 'set-analysts', kind: 'member', name: 'Analysts', permissions: [...READ_ONLY] })
  db().seedSet({ id: 'set-unused', kind: 'member', name: 'Unused', permissions: ['graph:read'] })
  db().seedSet({ id: 'set-manager', kind: 'admin', name: 'Manager', permissions: ['admins:manage', 'users:read'] })
  db().seedAssignment('admin-r', 'set-analysts')
  db().seedAssignment('member-1', 'set-analysts')
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 1 }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
})

describe('GET', () => {
  test('roles:manage lists the built-ins first, then the stored member sets, with holders and the default', async () => {
    db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date(0), defaultMemberSetId: 'set-unused' })
    const { status, body } = await list('admin-1')
    expect(status).toBe(200)
    const sets = body.sets as Array<{ id: string; builtin: boolean; holders: number; instanceDefault: boolean; kind: string }>
    expect(sets.map((s) => s.id)).toEqual([
      'builtin:default-member', 'builtin:read-only-analyst', 'builtin:recon-operator', 'builtin:red-team-operator',
      'builtin:automation', 'builtin:no-access', 'set-analysts', 'set-unused',
    ])
    expect(sets.every((s) => s.kind === 'member')).toBe(true)
    expect(sets.find((s) => s.id === 'set-analysts')).toMatchObject({ builtin: false, holders: 2, instanceDefault: false })
    expect(sets.find((s) => s.id === 'set-unused')).toMatchObject({ holders: 0, instanceDefault: true })
    expect(body.instanceDefaultSetId).toBe('set-unused')
  })

  test('users:assign_permissions lists them too (the picker); anyone else 403 roles:manage', async () => {
    expect((await list('admin-u')).status).toBe(200)
    expect((await list('admin-p')).body).toMatchObject({ code: 'forbidden', permission: 'roles:manage' })
    expect((await list('member-1')).body).toMatchObject({ code: 'forbidden', permission: 'roles:manage' })
    h.jar = {}
    expect((await GET()).status).toBe(401)
  })
})

describe('POST', () => {
  test('creates a set of known member permissions, in registry order, with its audit row', async () => {
    const r = await create('admin-1', { name: '  Triage desk ', description: 'Board only', permissions: ['triage:verdict', 'triage:read'] })
    expect(r.status).toBe(201)
    expect(r.body.set).toMatchObject({ kind: 'member', name: 'Triage desk', description: 'Board only', permissions: ['triage:read', 'triage:verdict'], builtin: false, createdById: 'admin-1' })
    const id = (r.body.set as { id: string }).id
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'permission_set.created', targetType: 'permission_set', targetId: id, actorId: 'admin-1', permission: 'roles:manage',
    })])
  })

  test('clones a built-in or a stored set', async () => {
    const r = await create('admin-1', { name: 'Recon copy', cloneFrom: 'builtin:recon-operator' })
    expect(r.body.set).toMatchObject({ permissions: RECON, clonedFrom: 'builtin:recon-operator' })
    expect((await create('admin-1', { name: 'Admins copy', cloneFrom: 'set-manager' })).body.code).toBe('unknown_set')
  })

  test('a name taken by a built-in or another set, ignoring case, is refused', async () => {
    expect((await create('admin-1', { name: 'default MEMBER', permissions: [] })).status).toBe(409)
    expect((await create('admin-1', { name: 'analysts', permissions: [] })).body.code).toBe('name_taken')
    expect((await create('admin-1', { name: 'manager', permissions: [] })).body.code).toBe('name_taken')
  })

  test.each([
    [{ permissions: [] }, 'invalid_name'],
    [{ name: 'x'.repeat(81), permissions: [] }, 'invalid_name'],
    [{ name: 'Mixed', permissions: ['recon:scan', 'users:read'] }, 'wrong_kind'],
    [{ name: 'Unknown', permissions: ['recon:everything'] }, 'unknown_permission'],
    [{ name: 'Twice', permissions: ['recon:scan', 'recon:scan'] }, 'invalid_permissions'],
    [{ name: 'Nothing' }, 'invalid_permissions'],
  ])('%j → 400 %s', async (body, code) => {
    const before = state()
    expect(await create('admin-1', body)).toMatchObject({ status: 400, body: { code } })
    expect(state()).toBe(before)
  })

  test('only permissions the creator holds (PE-11)', async () => {
    const before = state()
    const r = await create('admin-r', { name: 'Scanners', permissions: ['graph:read', 'recon:scan'] })
    expect(r).toMatchObject({ status: 403, body: { code: 'not_held', permissions: ['recon:scan'] } })
    expect(state()).toBe(before)
  })

  test('roles:manage only; cross-origin refused', async () => {
    expect((await create('admin-u', { name: 'X', permissions: [] })).body).toMatchObject({ code: 'forbidden', permission: 'roles:manage' })
    expect((await create('member-1', { name: 'X', permissions: [] })).status).toBe(403)
    const before = state()
    expect((await create('admin-1', { name: 'X', permissions: [] }, 'https://evil.example')).body.code).toBe('cross_origin')
    expect(state()).toBe(before)
  })

  test('audit failure → no change', async () => {
    db().failAudit('permission_set.created')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const before = state()
    expect((await create('admin-1', { name: 'Lost', permissions: ['graph:read'] })).status).toBe(500)
    err.mockRestore()
    expect(state()).toBe(before)
  })
})

describe('PUT', () => {
  test('set edit adds only held: self-edit of one\'s own set cannot add', async () => {
    const before = state()
    const r = await edit('admin-r', 'set-analysts', { permissions: [...READ_ONLY, 'recon:scan'] })
    expect(r).toMatchObject({ status: 403, body: { code: 'not_held', permissions: ['recon:scan'] } })
    expect(state()).toBe(before)
    expect(await held('admin-r')).not.toContain('recon:scan')
  })

  test('what the editor holds is added; holders gain it, nobody is signed out', async () => {
    const r = await edit('admin-1', 'set-analysts', { permissions: [...READ_ONLY, 'recon:scan'] })
    expect(r).toMatchObject({ status: 200, body: { changed: true, added: ['recon:scan'], removed: [], signedOut: 0 } })
    expect(await held('member-1')).toContain('recon:scan')
    expect(db().account('member-1')!.sessionVersion).toBe(0)
    expect(wsClosedFor()).toEqual([])
    expect(db().audit().map((a) => a.action)).toEqual(['permission_set.updated'])
  })

  test('adding an exploitation approval, sessions or Kali exec takes the editor\'s password', async () => {
    const body = { permissions: [...READ_ONLY, 'agent:kali_exec'] }
    expect((await edit('admin-1', 'set-analysts', body)).body.code).toBe('step_up_required')
    expect((await edit('admin-1', 'set-analysts', { ...body, stepUpPassword: pw('admin-1') })).status).toBe(200)
  })

  test('a removal signs out every holder (sv and sockets), and no one else', async () => {
    const r = await edit('admin-1', 'set-analysts', { permissions: READ_ONLY.filter((p) => p !== 'graph:read') })
    expect(r).toMatchObject({ status: 200, body: { removed: ['graph:read'], signedOut: 2 } })
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(db().account('admin-r')!.sessionVersion).toBe(1)
    expect(db().account('member-2')!.sessionVersion).toBe(0)
    expect(wsClosedFor().sort()).toEqual(['admin-r', 'member-1'])
    expect(await held('member-1')).not.toContain('graph:read')
  })

  test('a rename only: no sign-out; a name taken: 409', async () => {
    expect(await edit('admin-1', 'set-analysts', { name: 'Analyst team' })).toMatchObject({ status: 200, body: { signedOut: 0, set: { name: 'Analyst team', holders: 2 } } })
    expect((await edit('admin-1', 'set-analysts', { name: 'UNUSED' })).body.code).toBe('name_taken')
  })

  test('built-ins are read-only; an admin profile is not a member set; unknown ids 404', async () => {
    expect((await edit('admin-1', 'builtin:recon-operator', { name: 'Mine' })).body.code).toBe('builtin_read_only')
    expect((await edit('admin-1', 'set-manager', { name: 'Mine' })).status).toBe(404)
    expect((await edit('admin-1', 'builtin:full-admin', { instanceDefault: true })).status).toBe(404)
    expect((await edit('admin-1', 'nope', { name: 'Mine' })).status).toBe(404)
  })

  test('audit failure → no change, nobody signed out', async () => {
    db().failAudit('permission_set.updated')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const before = state()
    expect((await edit('admin-1', 'set-analysts', { permissions: [] })).status).toBe(500)
    err.mockRestore()
    expect(state()).toBe(before)
    expect(wsClosedFor()).toEqual([])
  })
})

describe('the instance default (instance:settings, Root)', () => {
  test('a Full admin cannot choose it: 403 root_only', async () => {
    const before = state()
    expect((await edit('admin-1', 'set-unused', { instanceDefault: true, stepUpPassword: pw('admin-1') })).body.code).toBe('root_only')
    expect(state()).toBe(before)
  })

  test('Root chooses it with its password; never-assigned members who lose a permission are signed out', async () => {
    expect((await edit(ROOT, 'builtin:read-only-analyst', { instanceDefault: true })).body.code).toBe('step_up_required')
    const r = await edit(ROOT, 'builtin:read-only-analyst', { instanceDefault: true, stepUpPassword: pw(ROOT) })
    expect(r).toMatchObject({ status: 200, body: { changed: true, set: { id: 'builtin:read-only-analyst', instanceDefault: true }, signedOut: 2 } })
    expect(db().instance()!.defaultMemberSetId).toBe('builtin:read-only-analyst')
    expect(['member-1', 'member-2', 'member-3'].map((id) => db().account(id)!.sessionVersion)).toEqual([0, 1, 1])
    expect(await held('member-2')).not.toContain('recon:scan')
    expect(db().audit().map((a) => [a.action, a.permission])).toEqual([['instance.default_member_set_changed', 'instance:settings']])
    const back = await edit(ROOT, 'builtin:read-only-analyst', { instanceDefault: false, stepUpPassword: pw(ROOT) })
    expect(back).toMatchObject({ status: 200, body: { signedOut: 0, set: { instanceDefault: false } } })
    expect(db().instance()!.defaultMemberSetId).toBeNull()
    expect(await held('member-2')).toContain('recon:scan')
  })
})

describe('DELETE (PE-17)', () => {
  test('delete in use refused', async () => {
    const before = state()
    expect(await remove('admin-1', 'set-analysts')).toMatchObject({ status: 409, body: { code: 'set_in_use', holders: 2 } })
    expect(state()).toBe(before)
  })

  test('delete default refused', async () => {
    db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date(0), defaultMemberSetId: 'set-unused' })
    const before = state()
    expect(await remove('admin-1', 'set-unused')).toMatchObject({ status: 409, body: { code: 'set_is_default' } })
    expect(state()).toBe(before)
  })

  test('an unused set is deleted with its audit row; a second delete is 404', async () => {
    expect(await remove('admin-1', 'set-unused')).toMatchObject({ status: 200, body: { id: 'set-unused', deleted: true } })
    expect(db().sets().map((s) => s.id)).not.toContain('set-unused')
    expect(db().audit()).toEqual([expect.objectContaining({ action: 'permission_set.deleted', targetId: 'set-unused', permission: 'roles:manage' })])
    expect((await remove('admin-1', 'set-unused')).status).toBe(404)
  })

  test('built-ins and admin profiles are not deleted here; cross-origin refused; audit failure keeps the set', async () => {
    expect((await remove('admin-1', 'builtin:no-access')).body.code).toBe('builtin_read_only')
    expect((await remove('admin-1', 'set-manager')).status).toBe(404)
    expect((await remove('admin-1', 'set-unused', 'https://evil.example')).body.code).toBe('cross_origin')
    db().failAudit('permission_set.deleted')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect((await remove('admin-1', 'set-unused')).status).toBe(500)
    err.mockRestore()
    expect(db().sets().map((s) => s.id)).toContain('set-unused')
  })
})
