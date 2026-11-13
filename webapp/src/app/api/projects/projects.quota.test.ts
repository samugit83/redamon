/**
 * Project quota (step 6.8, GV-09): POST /api/projects and POST /api/projects/import count the projects
 * the new project's owner (the caller's effective user) already owns against their maxProjects. At the
 * limit both answer 409 `quota_exceeded {quota: 'maxProjects', limit}` and create nothing; the import
 * refuses before it reads the upload. Under the limit, unlimited, or with RBAC_GOVERNANCE_ENABLED off
 * (nothing read) they go on as before. The resolution is the real lib/authz/quotas.ts over a doubled
 * instance row, account and capability resolution.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/projects/projects.quota.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  quotas: {} as unknown,
  owned: 0,
  create: vi.fn(),
  count: vi.fn(),
  instanceRead: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: vi.fn(async () => ({ id: 'user-1' })) },
    project: {
      create: (...a: unknown[]) => h.create(...a),
      update: vi.fn(),
      count: async (...a: unknown[]) => { h.count(...a); return h.owned },
    },
    userLlmProvider: { findFirst: vi.fn() },
  },
}))
vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => { h.instanceRead(); return { quotas: h.quotas } },
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => ({ id, role: 'standard', status: 'active', legacyGrants: [], permissionSets: ['cset-1'], permissionOverrides: [] }),
}))
vi.mock('@/lib/authz/capabilities', () => ({
  resolveCapabilities: async () => ({ accountType: 'member', sets: [{ id: 'cset-1', name: 'Lab', kind: 'member', via: 'assigned' }] }),
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() }),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { NextRequest } from 'next/server'
import { POST as create } from './route'
import { POST as importProject } from './import/route'
import { setFlagsForTests } from '@/lib/authz/flags'

const GOV_ON = { identity: true, permissions: true, governance: true }

const createReq = () => new NextRequest('http://localhost:3000/api/projects', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ name: 'p', targetDomain: 'example.invalid', targetGuardrailEnabled: false }),
})
// No file: past the quota the import answers 400 "No file uploaded", so the test needs no archive.
const importReq = () => {
  const form = new FormData()
  form.set('note', 'no file')
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: form })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.create.mockResolvedValue({ id: 'p1', name: 'p', userId: 'user-1', targetDomain: 'example.invalid' })
  h.quotas = { defaults: { maxProjects: 1 }, perSet: { 'cset-1': { maxProjects: 2 } } }
  h.owned = 0
  setFlagsForTests(GOV_ON)
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('project quota: create', () => {
  test('under the limit (the set\'s 2 over the default 1) the project is created', async () => {
    h.owned = 1
    expect((await create(createReq())).status).toBe(201)
    expect(h.count).toHaveBeenCalledWith({ where: { userId: 'user-1' } })
    expect(h.create).toHaveBeenCalledTimes(1)
  })

  test('at the limit: 409 quota_exceeded, nothing created, the refusal logged', async () => {
    h.owned = 2
    const res = await create(createReq())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'quota_exceeded', quota: 'maxProjects', limit: 2 })
    expect(h.create).not.toHaveBeenCalled()
    expect(console.warn).toHaveBeenCalledWith('[rbac] quota_exceeded quota=maxProjects user=user-1 limit=2 used=2')
  })

  test('unlimited ({}): nothing counted', async () => {
    h.quotas = {}
    h.owned = 500
    expect((await create(createReq())).status).toBe(201)
    expect(h.count).not.toHaveBeenCalled()
  })

  test('switch off: nothing enforced and nothing read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.owned = 50
    expect((await create(createReq())).status).toBe(201)
    expect(h.instanceRead).not.toHaveBeenCalled()
    expect(h.count).not.toHaveBeenCalled()
  })
})

describe('project quota: import', () => {
  test('at the limit: 409 before the upload is read', async () => {
    h.owned = 2
    const res = await importProject(importReq())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'quota_exceeded', quota: 'maxProjects', limit: 2 })
  })

  test('under the limit, unlimited and switch off: the import goes on (here to its own 400 for the missing file)', async () => {
    h.owned = 1
    expect((await importProject(importReq())).status).toBe(400)
    h.quotas = {}
    h.owned = 9
    expect((await importProject(importReq())).status).toBe(400)
    setFlagsForTests(null)
    h.quotas = { defaults: { maxProjects: 0 } }
    expect((await importProject(importReq())).status).toBe(400)
  })
})
