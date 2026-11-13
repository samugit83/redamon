/**
 * PUT /api/projects/[id] on a project shared at Read + Write (step 5.2; SH-28, SH-40, AU-01):
 *   - a collaborator's save answers the row as their GET reads it (projectReadView): never the owner's
 *     secret columns (credentials, header lists, the RoE parse), which the full row carried;
 *   - its audit row names the collaborator (and an admin acting as the owner, with whom they act for);
 *   - a stale save is 409 `{error: STALE_SAVE_MESSAGE, code: 'stale_save'}`, so a single-field save can
 *     tell it from the PUT's other 409s and reload (lib/projectFieldSave.ts).
 * The owner's answer still carries every column.
 *
 * The guard is doubled with the access each case needs; Prisma, the audit writer and the graph seed
 * are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  access: null as unknown,
  real: 'owner',
  effective: 'owner',
  audit: vi.fn(),
  updateMany: vi.fn(),
}))

const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test', subdomainList: ['www'],
  ipMode: false, domainBatchMode: false, domainBatchHosts: [], domainBatchGroups: null, targetIps: [],
  targetGuardrailEnabled: true, engagementKind: 'internal', ipHostnameMode: 'ip_only', ipHostnameInclude: [],
  ipHostnameExclude: [], ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100,
  ipHostnamePassiveMaxNames: 500, naabuRateLimit: 100, attackSkillConfig: null,
  cypherfixGithubToken: 'rbac-fake-token-0001', httpxCustomHeaders: ['X-Api-Key: rbac-fake-header-0001'],
  roeRawText: 'rbac-fake-roe-text', roeTimeWindowEnabled: false, roeTimeWindowDays: [],
  updatedAt: new Date('2026-11-13T10:00:00.000Z'),
}
let stored: Record<string, unknown> = {}

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async () => ({ ...stored }),
      update: async ({ data }: { data: Record<string, unknown> }) => (stored = { ...stored, ...data, updatedAt: new Date('2026-11-13T11:00:00.000Z') }),
      updateMany: (...a: unknown[]) => h.updateMany(...a),
    },
    userSettings: { findUnique: async () => null },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/graphSeedDomains', async () => {
  const actual = await vi.importActual<typeof import('@/lib/graphSeedDomains')>('@/lib/graphSeedDomains')
  return { ...actual, seedProjectDomains: async () => undefined }
})
vi.mock('@/lib/recordingSession', () => ({ refreshActiveRecordingScope: async () => undefined }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', async () => {
  const real = await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')
  return {
    ...real,
    requirePermission: async (_req: Request, permission: string) => ({
      session: { userId: h.real, role: 'standard' },
      principal: { id: h.real, role: 'standard', email: `${h.real}@rbac.test` },
      actingAs: h.real === h.effective ? null : { id: h.effective },
      effective: { userId: h.effective },
      permission,
      capabilities: { has: () => true },
      access: h.access,
    }),
  }
})

import { PUT } from './route'
import { SHARE_SECRET_FIELDS } from '@/lib/authz/projectReadView'
import { STALE_SAVE_MESSAGE } from '@/lib/projectVersion'

const P = { id: 'proj-1', userId: 'owner' }
const OWNER = { project: P, level: 'owner', toggles: { rawData: true }, via: 'owner' }
const EDITOR = { project: P, level: 'write', toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: false }, via: 'share' }

const put = (body: Record<string, unknown>) => PUT(
  new NextRequest('http://localhost/api/projects/proj-1', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  { params: Promise.resolve({ id: 'proj-1' }) },
)

beforeEach(() => {
  vi.clearAllMocks()
  stored = { ...STORED }
  h.updateMany.mockResolvedValue({ count: 1 })
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ allowed: true }) })))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("a collaborator's save on a write share (step 5.2)", () => {
  beforeEach(() => {
    h.access = EDITOR
    h.real = 'collab'
    h.effective = 'collab'
  })

  test("the answer is the row as the collaborator's GET reads it: no secret column", async () => {
    const res = await put({ naabuRateLimit: 50 })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.naabuRateLimit).toBe(50)
    for (const key of SHARE_SECRET_FIELDS) expect([key, key in body]).toEqual([key, false])
    expect(JSON.stringify(body)).not.toContain('rbac-fake')
  })

  test('the audit row names the collaborator', async () => {
    await put({ naabuRateLimit: 50 })
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ action: 'project.update', actorId: 'collab', targetId: 'proj-1' }))
    expect(h.audit.mock.calls[0][0]).not.toHaveProperty('onBehalfOfUserId')
  })

  test("a stale single-field save is 409 coded stale_save, nothing else changes", async () => {
    h.updateMany.mockResolvedValue({ count: 0 })
    const res = await put({ naabuRateLimit: 50, updatedAt: '2026-11-13T09:00:00.000Z' })
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: STALE_SAVE_MESSAGE, code: 'stale_save' })
    expect(h.audit).not.toHaveBeenCalled()
  })
})

describe('owner unchanged', () => {
  beforeEach(() => {
    h.access = OWNER
    h.real = 'owner'
    h.effective = 'owner'
  })

  test('the answer carries every column; the audit actor is the owner', async () => {
    const body = await (await put({ naabuRateLimit: 50 })).json()
    expect(body.cypherfixGithubToken).toBe('rbac-fake-token-0001')
    expect(body.httpxCustomHeaders).toEqual(['X-Api-Key: rbac-fake-header-0001'])
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ actorId: 'owner' }))
  })

  test('an admin acting as the owner is named, on behalf of the owner (AU-01)', async () => {
    h.real = 'admin-1'
    await put({ naabuRateLimit: 50 })
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ actorId: 'admin-1', onBehalfOfUserId: 'owner' }))
  })
})
