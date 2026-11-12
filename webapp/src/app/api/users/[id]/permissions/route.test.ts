/**
 * GET/PUT /api/users/[id]/permissions (step 3.11; PE-03, PE-08, PE-09, PE-10, PE-15, PE-30, ID-21,
 * ID-25): who reads and changes an account's sets, overrides and admin profile, that nobody gives
 * what they do not hold, the step-up, the sign-out on a removal, and the audit row that commits with
 * the change (fail closed).
 *
 * Real session helpers, tokens, bcrypt, step-up, resolution and hierarchy; the database is the
 * in-memory accountDb (transactions roll back); the agent is a fetch double.
 *
 * Run: npx vitest run --no-file-parallelism 'src/app/api/users/[id]/permissions/route.test.ts'
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')
vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')

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
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests, loadPrincipal } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests, resolveCapabilities } from '@/lib/authz/capabilities'
import { setNowForTests } from '@/lib/authz/clock'
import { builtinSet, FULL_ADMIN_PROFILE_ID } from '@/lib/authz/builtinSets'
import { __resetThrottle } from '@/lib/loginThrottle'
import { GET, PUT } from './route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const ACCOUNTS = [ROOT, 'admin-1', 'admin-m', 'admin-u', 'admin-r', 'admin-s', 'member-1', 'member-2']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))
const FULL_ADMIN = [...builtinSet(FULL_ADMIN_PROFILE_ID)!.permissions]
const NOW = new Date('2026-11-12T10:00:00Z')

function req(method: string, body?: unknown, origin?: string): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json' }
  if (origin) headers.origin = origin
  return new NextRequest('http://redamon.test/api/users/x/permissions', {
    method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function signIn(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

async function put(actor: string, target: string, body: Record<string, unknown>, origin?: string) {
  await signIn(actor)
  const res = await PUT(req('PUT', body, origin), params(target))
  return { res, body: await res.clone().json().catch(() => ({})) as Record<string, unknown> }
}

async function get(actor: string, target: string) {
  await signIn(actor)
  const res = await GET(req('GET'), params(target))
  return { res, body: await res.clone().json().catch(() => ({})) as Record<string, unknown> }
}

/** Everything a refused change could have touched. */
function state() {
  return JSON.stringify({
    users: ACCOUNTS.map((id) => db().account(id)), assignments: db().assignments(), overrides: db().overrides(),
    audit: db().audit().filter((a) => a.action !== 'rbac.root_protected_refused'),
  })
}

async function held(userId: string): Promise<readonly string[]> {
  clearPrincipalCacheForTests()
  return (await resolveCapabilities((await loadPrincipal(userId, { fresh: true }))!, { fresh: true })).held
}

const wsCloses = () => fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/ws/close'))

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', password: HASH[ROOT] },
    { id: 'admin-1', role: 'admin', password: HASH['admin-1'] },
    { id: 'admin-m', role: 'admin', password: HASH['admin-m'], adminProfileId: 'set-manager' },
    { id: 'admin-u', role: 'admin', password: HASH['admin-u'], adminProfileId: 'builtin:user-manager' },
    { id: 'admin-r', role: 'admin', password: HASH['admin-r'] },
    { id: 'admin-s', role: 'admin', password: HASH['admin-s'], adminProfileId: 'set-manager' },
    { id: 'member-1', password: HASH['member-1'] },
    { id: 'member-2', password: HASH['member-2'] },
  ])
  db().seedSet({ id: 'set-manager', kind: 'admin', name: 'Manager', permissions: [...FULL_ADMIN, 'admins:manage'] })
  db().seedSet({ id: 'set-recon', kind: 'member', name: 'Recon team', permissions: [...builtinSet('builtin:recon-operator')!.permissions] })
  db().seedAssignment('admin-r', 'builtin:read-only-analyst')
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  setNowForTests(() => NOW)
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
  setNowForTests(null)
  vi.unstubAllGlobals()
})

describe('GET: what an account holds, and why', () => {
  test('the account itself reads its own: sets in force, every permission with its reasons', async () => {
    const { res, body } = await get('member-1', 'member-1')
    expect(res.status).toBe(200)
    expect(body).toMatchObject({ userId: 'member-1', accountType: 'member', enforced: true, assignment: { sets: [], overrides: [] } })
    expect(body.assignment).not.toHaveProperty('adminProfileId')
    expect((body.sets as Array<{ id: string; via: string }>).map((s) => [s.id, s.via])).toEqual([['builtin:default-member', 'default']])
    const explain = body.explain as Array<{ permission: string; held: boolean; reasons: Array<{ kind: string }> }>
    expect(explain.length).toBe(98)
    expect(explain.find((e) => e.permission === 'recon:scan')).toMatchObject({ held: true })
    expect(explain.find((e) => e.permission === 'users:read')).toMatchObject({ held: false, reasons: [{ kind: 'not_granted' }] })
  })

  test('another member: users:assign_permissions; a member without it gets 403 naming it', async () => {
    expect((await get('admin-u', 'member-1')).res.status).toBe(200)
    const { res, body } = await get('member-2', 'member-1')
    expect(res.status).toBe(403)
    expect(body).toMatchObject({ code: 'forbidden', permission: 'users:assign_permissions' })
  })

  test('another admin: Root, or admins:manage over a strict subset; a Full admin gets root_only', async () => {
    const root = await get(ROOT, 'admin-1')
    expect(root.res.status).toBe(200)
    expect(root.body.assignment).toEqual({ sets: [], overrides: [], adminProfileId: null })
    expect((await get('admin-m', 'admin-1')).res.status).toBe(200)
    expect((await get('admin-1', 'admin-u')).body).toMatchObject({ code: 'root_only' })
    expect((await get('admin-m', 'admin-s')).body).toMatchObject({ code: 'not_a_subset' })
  })

  test('Root is read by Root alone; an unknown account is 404', async () => {
    expect((await get('admin-1', ROOT)).body).toMatchObject({ code: 'root_protected' })
    expect((await get(ROOT, ROOT)).res.status).toBe(200)
    expect((await get(ROOT, 'nobody')).res.status).toBe(404)
  })

  test('no session: 401', async () => {
    h.jar = {}
    expect((await GET(req('GET'), params('member-1'))).status).toBe(401)
  })
})

describe('PUT: who', () => {
  test('nobody changes their own permissions', async () => {
    const before = state()
    const { res, body } = await put('admin-1', 'admin-1', { sets: ['builtin:no-access'] })
    expect([res.status, body.code]).toEqual([400, 'own_account'])
    expect(state()).toBe(before)
  })

  test('nobody but Root acts on Root: 403 root_protected, recorded', async () => {
    const before = state()
    const { res, body } = await put('admin-1', ROOT, { sets: ['builtin:no-access'] })
    expect([res.status, body.code]).toEqual([403, 'root_protected'])
    expect(state()).toBe(before)
    expect(db().audit().map((a) => [a.action, (a.after as { attempted: string }).attempted])).toEqual([['rbac.root_protected_refused', 'change_permissions']])
  })

  test('a member target needs users:assign_permissions; a Platform operator profile lacks it', async () => {
    db().seedUsers([{ id: 'admin-p', role: 'admin', password: HASH['admin-1'], adminProfileId: 'builtin:platform-operator' }])
    const before = state()
    const { res, body } = await put('admin-p', 'member-1', { sets: ['builtin:read-only-analyst'] })
    expect([res.status, body.code, body.permission]).toEqual([403, 'forbidden', 'users:assign_permissions'])
    expect(state()).toBe(before)
  })

  test('an admin target is Root\'s: a Full admin gets root_only before any password is asked', async () => {
    const before = state()
    const { res, body } = await put('admin-1', 'admin-u', { adminProfileId: 'builtin:security-auditor', stepUpPassword: 'wrong' })
    expect([res.status, body.code]).toEqual([403, 'root_only'])
    expect(state()).toBe(before)
  })

  test('cross-origin: 403, nothing changes', async () => {
    const before = state()
    const { res, body } = await put(ROOT, 'member-1', { sets: ['builtin:no-access'] }, 'https://evil.example')
    expect([res.status, body.code]).toEqual([403, 'cross_origin'])
    expect(state()).toBe(before)
  })

  test('a body that is not JSON: 415', async () => {
    await signIn(ROOT)
    const r = new NextRequest('http://redamon.test/api/users/member-1/permissions', {
      method: 'PUT', headers: { host: 'redamon.test', 'content-type': 'text/plain' }, body: 'sets=builtin:no-access',
    })
    expect((await PUT(r, params('member-1'))).status).toBe(415)
  })
})

describe('PUT: no escalation (PE-03, PE-10)', () => {
  test('assign only held: an admin whose member side is Read-only analyst cannot assign Recon operator', async () => {
    const before = state()
    const { res, body } = await put('admin-r', 'member-1', { sets: ['set-recon'] })
    expect([res.status, body.code]).toEqual([403, 'not_held'])
    expect(body.permissions).toContain('recon:scan')
    expect(state()).toBe(before)
  })

  test('the same admin may assign what it holds (Read-only analyst), which only removes', async () => {
    const { res, body } = await put('admin-r', 'member-1', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(200)
    expect(body).toMatchObject({ changed: true, added: [], signedOut: true })
  })

  test('lifting a deny gives the permission back: only a holder may lift it', async () => {
    db().seedAssignment('member-1', 'builtin:read-only-analyst')
    db().seedOverride({ userId: 'member-1', permission: 'graph:read', effect: 'deny' })
    db().seedOverride({ userId: 'member-2', permission: 'recon:scan', effect: 'deny' })
    expect((await put('admin-r', 'member-1', { overrides: [] })).res.status).toBe(200)
    const before = state()
    const { res, body } = await put('admin-r', 'member-2', { overrides: [] })
    expect([res.status, body.code, body.permissions]).toEqual([403, 'not_held', ['recon:scan']])
    expect(state()).toBe(before)
  })

  test('the instance caps do not stop an admin giving what it holds (MCP and loop off)', async () => {
    db().seedAssignment('member-1', 'builtin:no-access')
    const { res, body } = await put('admin-1', 'member-1', { sets: ['builtin:automation'] })
    expect(res.status).toBe(200)
    expect(body.added).not.toContain('self:mcp_tokens')
    expect(await held('member-1')).not.toContain('self:mcp_tokens')
  })
})

describe('PUT: step-up (ID-25)', () => {
  test('granting a crossTenant permission needs step-up', async () => {
    const grant = { overrides: [{ permission: 'platform:kali_terminal', effect: 'grant', reason: 'ticket 42' }] }
    const before = state()
    const missing = await put('admin-1', 'member-1', grant)
    expect([missing.res.status, missing.body.code]).toEqual([403, 'step_up_required'])
    const wrong = await put('admin-1', 'member-1', { ...grant, stepUpPassword: 'not-it' })
    expect([wrong.res.status, wrong.body.code]).toEqual([403, 'step_up_failed'])
    expect(state()).toBe(before)
    const ok = await put('admin-1', 'member-1', { ...grant, stepUpPassword: pw('admin-1') })
    expect(ok.res.status).toBe(200)
    expect(ok.body).toMatchObject({ added: ['platform:kali_terminal'], signedOut: false })
    expect(await held('member-1')).toContain('platform:kali_terminal')
  })

  test('so do the exploitation approvals, sessions and Kali exec', async () => {
    db().seedAssignment('member-1', 'builtin:recon-operator')
    for (const permission of ['agent:approve_phase', 'agent:approve_dangerous', 'agent:sessions', 'agent:kali_exec']) {
      const { body } = await put('admin-1', 'member-1', { overrides: [{ permission, effect: 'grant' }] })
      expect([permission, body.code]).toEqual([permission, 'step_up_required'])
    }
    const recon = await put('admin-1', 'member-1', { overrides: [{ permission: 'recon:partial', effect: 'grant' }] })
    expect(recon.res.status).toBe(200)
  })

  test('any change to an admin takes the person\'s password, Root\'s too', async () => {
    const missing = await put(ROOT, 'admin-1', { adminProfileId: 'builtin:user-manager' })
    expect(missing.body.code).toBe('step_up_required')
    const ok = await put(ROOT, 'admin-1', { adminProfileId: 'builtin:user-manager', stepUpPassword: pw(ROOT) })
    expect(ok.res.status).toBe(200)
    expect(db().account('admin-1')!.adminProfileId).toBe('builtin:user-manager')
  })
})

describe('PUT: a removal signs the account out; an addition does not (ID-21)', () => {
  test('removal bumps sv and closes the sockets', async () => {
    const { res, body } = await put('admin-1', 'member-1', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(200)
    expect(body).toMatchObject({ changed: true, signedOut: true, added: [] })
    expect((body.removed as string[])).toContain('recon:scan')
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(wsCloses().length).toBe(1)
    expect(JSON.parse(String(wsCloses()[0][1].body))).toMatchObject({ user_id: 'member-1' })
  })

  test('addition does not: the version stays, no socket closes', async () => {
    db().seedAssignment('member-1', 'builtin:read-only-analyst')
    const { res, body } = await put('admin-1', 'member-1', { sets: ['builtin:read-only-analyst', 'set-recon'] })
    expect(res.status).toBe(200)
    expect(body).toMatchObject({ changed: true, signedOut: false, removed: [] })
    expect(db().account('member-1')!.sessionVersion).toBe(0)
    expect(wsCloses()).toEqual([])
    expect(await held('member-1')).toContain('recon:scan')
  })

  test('the agent unreachable: the change and the sign-out stand, the failure is reported', async () => {
    fetchMock.mockImplementation(async () => { throw new TypeError('fetch failed') })
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { res, body } = await put('admin-1', 'member-1', { sets: ['builtin:no-access'] })
    expect(res.status).toBe(200)
    expect(body.agent).toEqual({ closed: 0, failed: 1 })
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(err.mock.calls.some(([line]) => String(line).startsWith('[rbac] socket-close failed user=member-1'))).toBe(true)
    err.mockRestore()
  })

  test('the same change twice: the second changes nothing', async () => {
    expect((await put('admin-1', 'member-1', { sets: ['builtin:no-access'] })).body.changed).toBe(true)
    const again = await put('admin-1', 'member-1', { sets: ['builtin:no-access'] })
    expect(again.body).toEqual({ id: 'member-1', changed: false })
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(db().audit().filter((a) => a.action === 'user.permissions_changed').length).toBe(1)
  })
})

describe('PUT: the audit row commits with the change', () => {
  test('one user.permissions_changed row: before and after, the effective sets, the real actor', async () => {
    await put('admin-1', 'member-1', { sets: ['builtin:read-only-analyst'] })
    const rows = db().audit().filter((a) => a.action === 'user.permissions_changed')
    expect(rows.length).toBe(1)
    expect(rows[0]).toMatchObject({ actorId: 'admin-1', targetType: 'user', targetId: 'member-1', permission: 'users:assign_permissions' })
    const before = rows[0].before as { sets: string[]; held: string[] }
    const after = rows[0].after as { sets: string[]; held: string[]; removed: string[]; sessionVersion: number }
    expect(before.sets).toEqual([])
    expect(after.sets).toEqual(['builtin:read-only-analyst'])
    expect(before.held).toContain('recon:scan')
    expect(after.held).not.toContain('recon:scan')
    expect(after.removed).toContain('recon:scan')
    expect(after.sessionVersion).toBe(1)
  })

  test('audit failure → no change: no rows, no sign-out, no socket closed', async () => {
    db().failAudit('user.permissions_changed')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const before = state()
    const { res, body } = await put('admin-1', 'member-1', { sets: ['builtin:no-access'] })
    err.mockRestore()
    expect(res.status).toBe(500)
    expect(JSON.stringify(body)).not.toContain('audit insert failed')
    expect(state()).toBe(before)
    expect(wsCloses()).toEqual([])
  })
})

describe('PUT: admins:manage (PE-09)', () => {
  test('promote only to a subset: the manager gives a strict subset of its own profile, never its own', async () => {
    const own = await put('admin-m', 'admin-u', { adminProfileId: 'set-manager', stepUpPassword: pw('admin-m') })
    expect([own.res.status, own.body.code]).toEqual([403, 'not_a_subset'])
    const ok = await put('admin-m', 'admin-u', { adminProfileId: 'builtin:full-admin', stepUpPassword: pw('admin-m') })
    expect(ok.res.status).toBe(200)
    expect(db().account('admin-u')!.adminProfileId).toBe('builtin:full-admin')
    expect(db().audit().find((a) => a.action === 'user.permissions_changed')).toMatchObject({ permission: 'admins:manage' })
  })

  test('equal profiles cannot manage each other', async () => {
    const before = state()
    const { res, body } = await put('admin-m', 'admin-s', { sets: ['builtin:no-access'], stepUpPassword: pw('admin-m') })
    expect([res.status, body.code]).toEqual([403, 'not_a_subset'])
    expect(state()).toBe(before)
  })

  test('one profile: an admin\'s profile is replaced, never added to; a member has none', async () => {
    await put(ROOT, 'admin-1', { adminProfileId: 'builtin:user-manager', stepUpPassword: pw(ROOT) })
    await put(ROOT, 'admin-1', { adminProfileId: 'builtin:security-auditor', stepUpPassword: pw(ROOT) })
    expect(db().account('admin-1')!.adminProfileId).toBe('builtin:security-auditor')
    expect(db().account('admin-1')!.sessionVersion).toBe(2)
    const member = await put(ROOT, 'member-1', { adminProfileId: 'builtin:user-manager' })
    expect([member.res.status, member.body.code]).toEqual([400, 'not_an_admin'])
    const memberSet = await put(ROOT, 'admin-1', { adminProfileId: 'builtin:default-member', stepUpPassword: pw(ROOT) })
    expect([memberSet.res.status, memberSet.body.code]).toEqual([400, 'unknown_profile'])
  })
})

describe('PUT: the body', () => {
  test.each([
    [{}, 'nothing_to_change'],
    [{ sets: 'builtin:no-access' }, 'invalid_sets'],
    [{ sets: ['builtin:no-access', 'builtin:no-access'] }, 'invalid_sets'],
    [{ sets: ['builtin:full-admin'] }, 'unknown_set'],
    [{ sets: ['set-manager'] }, 'unknown_set'],
    [{ sets: ['nope'] }, 'unknown_set'],
    [{ overrides: [{ permission: 'nope:never', effect: 'grant' }] }, 'unknown_permission'],
    [{ overrides: [{ permission: 'recon:scan', effect: 'allow' }] }, 'invalid_overrides'],
    [{ overrides: [{ permission: 'users:read', effect: 'grant' }] }, 'admin_permission_override'],
  ])('%j → 400 %s, nothing written', async (body, code) => {
    const before = state()
    const r = await put('admin-1', 'member-1', body)
    expect([r.res.status, r.body.code]).toEqual([400, code])
    expect(state()).toBe(before)
  })
})
