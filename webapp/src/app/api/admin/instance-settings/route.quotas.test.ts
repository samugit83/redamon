/**
 * The quotas group of /api/admin/instance-settings (step 6.8; GV-09..GV-13, OQ-39). With
 * RBAC_GOVERNANCE_ENABLED on, whoever holds instance:quotas reads the stored quotas with the sets
 * the editor names (and the accounts, for a users:read holder) and changes them by patch: values
 * saved and audited (key names only), entries not named kept, bad values and unknown targets
 * refused before anything is written, no password asked. Anyone else neither sees nor changes them.
 * With the switch off the route is the one before: no quotas shown, none read from a body.
 *
 * Doubles: the session, the principal, the permission checks and the Root's standing; the instance
 * row, the sets, the accounts and the audit table are an in-memory Prisma under the real
 * writeInstanceSettings (one transaction with the audit row).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/instance-settings/route.quotas.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  held: new Set<string>(),
  role: 'admin',
  instance: null as Record<string, unknown> | null,
  audit: [] as Record<string, unknown>[],
  updates: 0,
  stepUp: vi.fn(),
  asked: [] as string[],
}))

vi.mock('@/lib/session', () => ({
  getSession: async () => ({ userId: 'adm-a', role: h.role, email: 'adm-a@e2e.local', name: 'adm-a' }),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => ({ id, role: h.role, status: 'active', legacyGrants: [] }),
}))
vi.mock('@/lib/authz/sharedTools', () => ({ sharedToolAccess: async () => ({ allowed: false, via: null }) }))
vi.mock('@/lib/authz/adminPermission', () => ({
  sessionHolds: async (_s: unknown, p: string) => {
    h.asked.push(p)
    return h.held.has(p)
  },
}))
vi.mock('@/lib/authz/rootPowers', async (orig) => ({ ...(await orig<object>()), rootStanding: async () => 'none' }))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: async (...a: unknown[]) => { h.stepUp(...a); return null } }))
vi.mock('@/lib/sharedSettingsEffects', () => ({
  CAPTURE_RECREATE_FIELDS: [], pushTunnelConfig: async () => null, reconcileCaptureProxy: async () => null,
}))
vi.mock('@/lib/prisma', () => {
  const clone = <T,>(v: T): T => structuredClone(v)
  const client = {
    instanceSettings: {
      findUnique: async () => clone(h.instance),
      update: async ({ data }: { data: Row }) => {
        h.updates += 1
        h.instance = { ...h.instance!, ...clone(data) }
        return clone(h.instance)
      },
    },
    auditLog: { create: async ({ data }: { data: Row }) => { h.audit.push(clone(data)); return data } },
    permissionSet: {
      findMany: async ({ where }: { where?: { id: { in: string[] } } }) => {
        const rows = [{ id: 'cset-1', name: 'Lab team', kind: 'member' }]
        return where ? rows.filter((r) => where.id.in.includes(r.id)).map((r) => ({ id: r.id })) : rows
      },
    },
    user: {
      findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
        [{ id: 'mem-c', email: 'mem-c@e2e.local', name: 'Mem C' }].filter((u) => where.id.in.includes(u.id)),
    },
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn(client),
  }
  return { default: client }
})

import { GET, PUT } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'

const GOV_ON = { identity: true, permissions: true, governance: true }

function instanceRow(quotas: unknown = {}): Row {
  return {
    id: 'instance', quotas, sharingPolicy: {}, tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '',
    tunnelSourceUserId: null, captureSourceUserId: null, passwordMinLength: 12,
  }
}

const put = (body: unknown) => PUT(new NextRequest('http://localhost:3000/api/admin/instance-settings', {
  method: 'PUT',
  headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
  body: JSON.stringify(body),
}))
const get = () => GET(new NextRequest('http://localhost:3000/api/admin/instance-settings'))

beforeEach(() => {
  h.held = new Set(['instance:quotas', 'users:read'])
  h.role = 'admin'
  h.instance = instanceRow({ defaults: { maxProjects: 3 }, perUser: { 'mem-c': { maxProjects: 1 } } })
  h.audit = []
  h.updates = 0
  h.asked = []
  h.stepUp.mockClear()
  setFlagsForTests(GOV_ON)
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('reading the quotas', () => {
  test('an instance:quotas holder reads them with every set and the accounts named', async () => {
    const body = await (await get()).json()
    expect(body.quotas).toEqual({ defaults: { maxProjects: 3 }, perSet: {}, perUser: { 'mem-c': { maxProjects: 1 } } })
    expect(body.canManageQuotas).toBe(true)
    expect(body.quotaSets).toEqual(expect.arrayContaining([
      { id: 'builtin:default-member', name: 'Default member', kind: 'member' },
      { id: 'builtin:full-admin', name: 'Full admin', kind: 'admin' },
      { id: 'cset-1', name: 'Lab team', kind: 'member' },
    ]))
    expect(body.quotaUsers).toEqual([{ id: 'mem-c', email: 'mem-c@e2e.local', name: 'Mem C' }])
  })

  test('without users:read the accounts are not named (the editor shows ids)', async () => {
    h.held.delete('users:read')
    const body = await (await get()).json()
    expect(body.quotas.perUser).toEqual({ 'mem-c': { maxProjects: 1 } })
    expect(body).not.toHaveProperty('quotaUsers')
  })

  test('an admin without instance:quotas does not see them', async () => {
    h.held = new Set()
    const body = await (await get()).json()
    expect(body).not.toHaveProperty('quotas')
    expect(body).not.toHaveProperty('quotaSets')
    expect(body.securityPolicy).toBeDefined()
  })

  test('an unreadable stored value reads as unlimited', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    h.instance = instanceRow('garbage')
    expect((await (await get()).json()).quotas).toEqual({ defaults: {}, perSet: {}, perUser: {} })
  })
})

describe('changing the quotas', () => {
  test('values saved and audited by key name, without a password', async () => {
    const res = await put({ quotas: {
      defaults: { maxProjects: 5, maxMcpTokenExpiryDays: 90, llmDailyCalls: null },
      perSet: { 'builtin:read-only-analyst': { maxConcurrentScans: 0 }, 'cset-1': { maxProjects: null } },
    } })
    expect(res.status).toBe(200)
    expect(h.instance!.quotas).toEqual({
      defaults: { maxProjects: 5, maxMcpTokenExpiryDays: 90, llmDailyCalls: null },
      perSet: { 'builtin:read-only-analyst': { maxConcurrentScans: 0 }, 'cset-1': { maxProjects: null } },
      perUser: { 'mem-c': { maxProjects: 1 } },
    })
    expect(h.stepUp).not.toHaveBeenCalled()
    expect(h.audit).toHaveLength(1)
    expect(h.audit[0]).toMatchObject({ action: 'instance.settings_changed', actorId: 'adm-a', targetType: 'instance' })
    const after = h.audit[0].after as Row
    expect(after.fields).toEqual(['quotas'])
    expect(after.changedKeys).toEqual({ quotas: ['defaults.maxProjects', 'defaults.maxMcpTokenExpiryDays', 'perSet.builtin:read-only-analyst', 'perSet.cset-1'] })
    expect(JSON.stringify(after)).not.toContain('90')
    const body = await res.json()
    expect(body.quotas.defaults.maxProjects).toBe(5)
    expect(body.canManageQuotas).toBe(true)
  })

  test('two admins changing two accounts never undo each other (entries not named are kept)', async () => {
    await put({ quotas: { perUser: { 'mem-d': { maxProjects: 2 } } } }).catch(() => null)
    // mem-d does not exist: refused, nothing written.
    expect(h.updates).toBe(0)
    await put({ quotas: { perUser: { 'mem-c': { maxMcpTokens: 1 } } } })
    await put({ quotas: { perSet: { 'cset-1': { maxProjects: 4 } } } })
    expect(h.instance!.quotas).toEqual({
      defaults: { maxProjects: 3 }, perSet: { 'cset-1': { maxProjects: 4 } }, perUser: { 'mem-c': { maxMcpTokens: 1 } },
    })
    await put({ quotas: { perUser: { 'mem-c': null } } })
    expect((h.instance!.quotas as Row).perUser).toEqual({})
  })

  test('a value out of bounds is 400 invalid_field naming it; nothing written', async () => {
    for (const quotas of [{ defaults: { maxProjects: -1 } }, { defaults: { maxMcpTokenExpiryDays: 0 } }, { perSet: { 'cset-1': { bogus: 1 } } }, 'x']) {
      const res = await put({ quotas })
      expect(res.status).toBe(400)
      expect((await res.json()).code).toBe('invalid_field')
    }
    expect(h.updates).toBe(0)
    expect(h.audit).toEqual([])
  })

  test('a new entry for a set or an account that does not exist is 400 unknown_quota_target', async () => {
    const res = await put({ quotas: { perSet: { 'builtin:nope': { maxProjects: 1 } }, perUser: { ghost: { maxProjects: 1 } } } })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'unknown_quota_target', sets: ['builtin:nope'], users: ['ghost'] })
    expect(h.updates).toBe(0)
  })

  test('an admin without instance:quotas is refused 403 naming the permission; nothing written', async () => {
    h.held = new Set()
    const res = await put({ quotas: { defaults: { maxProjects: 1 } } })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'instance:quotas', fields: ['defaults.maxProjects'] })
    expect(h.updates).toBe(0)
  })

  test('the same quotas sent again write nothing (no audit row)', async () => {
    const res = await put({ quotas: { defaults: { maxProjects: 3 }, perUser: { 'mem-c': { maxProjects: 1 } } } })
    expect(res.status).toBe(200)
    expect(h.updates).toBe(0)
    expect(h.audit).toEqual([])
  })
})

describe('RBAC_GOVERNANCE_ENABLED off: the route is the one before', () => {
  test('no quotas shown, none read from a body, instance:quotas never asked', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    const body = await (await get()).json()
    expect(body).not.toHaveProperty('quotas')
    const res = await put({ quotas: { defaults: { maxProjects: 1 } } })
    expect(res.status).toBe(200)
    expect(h.updates).toBe(0)
    expect((h.instance!.quotas as Row).defaults).toEqual({ maxProjects: 3 })
    expect(h.asked).not.toContain('instance:quotas')
  })
})
