/**
 * Per-account overrides (step 3.11; PE-01, PE-15, PE-30, D-20): a grant or a deny of one permission,
 * with an optional expiry and reason, written through PUT /api/users/[id]/permissions. What one may
 * name (a member permission; a platform tool on a member only; never an administration right),
 * what is kept, that a deny wins, that an expired override does nothing, and that renewing or
 * lengthening a grant counts as giving it.
 *
 * Real session helpers, tokens, bcrypt, step-up and resolution; the database is the in-memory
 * accountDb; the clock is injected; the agent is a fetch double.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/overrides.test.ts
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
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearPrincipalCacheForTests, loadPrincipal } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests, resolveCapabilities } from './capabilities'
import { PERMISSIONS, PERMISSION_IDS } from './permissions'
import { parseChange } from './userPermissionAdmin'
import { __resetThrottle } from '@/lib/loginThrottle'
import { GET, PUT } from '@/app/api/users/[id]/permissions/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries([ROOT, 'admin-1', 'admin-r'].map((id) => [id, bcrypt.hashSync(pw(id), 4)]))
let clock = new Date('2026-11-12T10:00:00Z')
const later = (minutes: number) => new Date(clock.getTime() + minutes * 60_000)

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x/permissions', {
    method,
    headers: { host: 'redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

async function put(actor: string, target: string, body: Record<string, unknown>) {
  await as(actor)
  const res = await PUT(req('PUT', body), params(target))
  return { status: res.status, body: await res.json().catch(() => ({})) as Record<string, unknown> }
}

async function capabilities(userId: string) {
  clearPrincipalCacheForTests()
  return resolveCapabilities((await loadPrincipal(userId, { fresh: true }))!, { fresh: true })
}

beforeEach(() => {
  clock = new Date('2026-11-12T10:00:00Z')
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', password: HASH[ROOT] },
    { id: 'admin-1', role: 'admin', password: HASH['admin-1'] },
    { id: 'admin-r', role: 'admin', password: HASH['admin-r'] },
    { id: 'member-1' },
  ])
  db().seedAssignment('admin-r', 'builtin:read-only-analyst')
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  setNowForTests(() => clock)
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
  setNowForTests(null)
  vi.unstubAllGlobals()
})

describe('what an override may name (D-20, PE-30)', () => {
  const ADMINISTRATION = PERMISSION_IDS.filter((p) => PERMISSIONS[p].kind === 'admin' && !PERMISSIONS[p].crossTenant)
  const PLATFORM = PERMISSION_IDS.filter((p) => PERMISSIONS[p].crossTenant)

  test('never an administration permission, on a member or an admin, grant or deny', () => {
    for (const permission of ADMINISTRATION) {
      for (const effect of ['grant', 'deny']) {
        for (const type of ['member', 'admin'] as const) {
          const r = parseChange({ overrides: [{ permission, effect }] }, type)
          expect([permission, effect, type, (r as Response).status]).toEqual([permission, effect, type, 400])
        }
      }
    }
  })

  test('a platform tool on a member (the §14.7 shared tools), never on an admin', () => {
    for (const permission of PLATFORM) {
      expect(parseChange({ overrides: [{ permission, effect: 'grant' }] }, 'member')).toMatchObject({ overrides: [{ permission }] })
      expect((parseChange({ overrides: [{ permission, effect: 'grant' }] }, 'admin') as Response).status).toBe(400)
    }
  })

  test('two overrides of one permission, an unknown one, or a bad effect are refused', async () => {
    for (const overrides of [
      [{ permission: 'recon:scan', effect: 'grant' }, { permission: 'recon:scan', effect: 'deny' }],
      [{ permission: 'recon:everything', effect: 'grant' }],
      [{ permission: 'recon:scan', effect: 'GRANT' }],
      [null],
      'recon:scan',
    ]) {
      const r = await put('admin-1', 'member-1', { overrides })
      expect([JSON.stringify(overrides), r.status]).toEqual([JSON.stringify(overrides), 400])
    }
    expect(db().overrides()).toEqual([])
  })
})

describe('expiry and reason', () => {
  test('expiry and reason saved, with who granted it; GET shows them', async () => {
    const expiresAt = later(60 * 24).toISOString()
    const r = await put('admin-1', 'member-1', {
      overrides: [{ permission: 'recon:scan', effect: 'deny', expiresAt, reason: '  ACME engagement paused  ' }],
    })
    expect(r.status).toBe(200)
    expect(db().overrides()).toEqual([expect.objectContaining({
      userId: 'member-1', permission: 'recon:scan', effect: 'deny', expiresAt: new Date(expiresAt),
      reason: 'ACME engagement paused', grantedById: 'admin-1',
    })])
    await as('member-1')
    const view = await (await GET(req('GET'), params('member-1'))).json()
    expect(view.assignment.overrides).toEqual([expect.objectContaining({
      permission: 'recon:scan', effect: 'deny', expiresAt, reason: 'ACME engagement paused', grantedById: 'admin-1',
    })])
  })

  test('an expiry already past, a date that does not parse, a reason too long: 400', async () => {
    for (const o of [
      { permission: 'recon:scan', effect: 'deny', expiresAt: clock.toISOString() },
      { permission: 'recon:scan', effect: 'deny', expiresAt: 'tomorrow' },
      { permission: 'recon:scan', effect: 'deny', expiresAt: 1767225600000 },
      { permission: 'recon:scan', effect: 'deny', reason: 'x'.repeat(501) },
    ]) {
      expect([o, (await put('admin-1', 'member-1', { overrides: [o] })).status]).toEqual([o, 400])
    }
    expect(db().overrides()).toEqual([])
  })
})

describe('effect after the write (PE-01)', () => {
  test('a deny wins over the set that grants it, until it expires', async () => {
    await put('admin-1', 'member-1', { overrides: [{ permission: 'recon:scan', effect: 'deny', expiresAt: later(30).toISOString() }] })
    const denied = await capabilities('member-1')
    expect(denied.has('recon:scan')).toBe(false)
    expect(denied.explain('recon:scan').reasons.map((r) => [r.kind, r.effect])).toEqual([['set', 'grant'], ['override', 'deny']])
    clock = later(31)
    expect((await capabilities('member-1')).has('recon:scan')).toBe(true)
  })

  test('replacing the overrides keeps the sets; replacing the sets keeps the overrides', async () => {
    db().seedAssignment('member-1', 'builtin:recon-operator')
    await put('admin-1', 'member-1', { overrides: [{ permission: 'recon:scan', effect: 'deny' }] })
    expect(db().assignments().filter((a) => a.userId === 'member-1').map((a) => a.setId)).toEqual(['builtin:recon-operator'])
    await put('admin-1', 'member-1', { sets: ['builtin:read-only-analyst'] })
    expect(db().overrides().map((o) => o.permission)).toEqual(['recon:scan'])
  })
})

describe('renewing or lengthening a grant gives it (PE-10)', () => {
  test('an expired grant gives nothing; granting it again needs a holder', async () => {
    db().seedAssignment('member-1', 'builtin:read-only-analyst')
    db().seedOverride({ userId: 'member-1', permission: 'recon:scan', effect: 'grant', expiresAt: later(-5) })
    expect((await capabilities('member-1')).has('recon:scan')).toBe(false)
    const again = { overrides: [{ permission: 'recon:scan', effect: 'grant', expiresAt: later(60).toISOString() }] }
    expect(await put('admin-r', 'member-1', again)).toMatchObject({ status: 403, body: { code: 'not_held', permissions: ['recon:scan'] } })
    expect(await put('admin-1', 'member-1', again)).toMatchObject({ status: 200, body: { added: ['recon:scan'] } })
  })

  test('lengthening a live grant counts too; shortening it, or a new reason, does not', async () => {
    db().seedAssignment('member-1', 'builtin:read-only-analyst')
    db().seedOverride({ userId: 'member-1', permission: 'recon:scan', effect: 'grant', expiresAt: later(60), reason: 'one hour' })
    const longer = { overrides: [{ permission: 'recon:scan', effect: 'grant', expiresAt: later(120).toISOString() }] }
    expect((await put('admin-r', 'member-1', longer)).body.code).toBe('not_held')
    expect((await put('admin-r', 'member-1', { overrides: [{ permission: 'recon:scan', effect: 'grant', expiresAt: later(60).toISOString(), reason: 'still one hour' }] })).status).toBe(200)
    expect((await put('admin-r', 'member-1', { overrides: [{ permission: 'recon:scan', effect: 'grant', expiresAt: later(30).toISOString() }] })).status).toBe(200)
    expect((await put('admin-r', 'member-1', { overrides: [{ permission: 'recon:scan', effect: 'grant' }] })).body.code).toBe('not_held')
  })

  test('removing an expired override removes nothing: nobody is signed out', async () => {
    db().seedOverride({ userId: 'member-1', permission: 'recon:partial', effect: 'grant', expiresAt: later(-5) })
    const r = await put('admin-1', 'member-1', { overrides: [] })
    expect(r).toMatchObject({ status: 200, body: { changed: true, removed: [], signedOut: false } })
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })
})
