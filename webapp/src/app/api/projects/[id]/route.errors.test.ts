/**
 * GET and PUT /api/projects/[id] failures: a fixed sentence plus a safe code
 * (Prisma code, class), never the exception's own text, which can quote query
 * values. PUT also says whether the row was written before the failure.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/projects/[id]/route.errors.test.ts"
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  update: vi.fn(),
  seed: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      update: (...a: unknown[]) => h.update(...a),
      updateMany: vi.fn(),
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/graphSeedDomains', () => ({
  seedDomainNames: () => [],
  seedProjectDomains: (...a: unknown[]) => h.seed(...a),
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => ({ userId: 'owner', isAdmin: false }),
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { GET, PUT } from './route'

const RAW = 'Invalid `prisma.project.update()` invocation: value "secret-target.example" too long'
const prismaError = (code: string) =>
  Object.assign(new Error(RAW), { code, name: 'PrismaClientKnownRequestError' })

const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test',
  ipMode: false, domainBatchMode: false, katanaDepth: 2,
  updatedAt: new Date('2026-09-29T10:00:00.000Z'),
}

const params = { params: Promise.resolve({ id: 'proj-1' }) }

function put(body: string) {
  return PUT(new NextRequest('http://localhost/api/projects/proj-1', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body,
  }), params)
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.findUnique.mockImplementation(async () => ({ ...STORED }))
  h.update.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...STORED, ...data }))
  h.seed.mockResolvedValue(undefined)
})

describe('GET', () => {
  test('a database failure answers the fixed sentence and the Prisma code', async () => {
    h.findUnique.mockRejectedValue(prismaError('P1001'))
    const res = await GET(new NextRequest('http://localhost/api/projects/proj-1'), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to fetch project', code: 'P1001' })
    expect(JSON.stringify(body)).not.toContain('secret-target')
  })
})

describe('PUT', () => {
  test('a body that is not JSON is a 400 invalid_json, not a 500', async () => {
    const res = await put('{not json')
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'The request body is not valid JSON.', code: 'invalid_json' })
    expect(h.update).not.toHaveBeenCalled()
  })

  test('a failed write answers its Prisma code and stage before_write', async () => {
    h.update.mockRejectedValue(prismaError('P2000'))
    const res = await put(JSON.stringify({ katanaDepth: 3 }))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to update project', code: 'P2000', stage: 'before_write' })
    expect(JSON.stringify(body)).not.toContain('secret-target')
  })

  test('a failure after the write says the project was saved', async () => {
    h.seed.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:7687'), { code: 'ECONNREFUSED' }))
    const res = await put(JSON.stringify({ katanaDepth: 3 }))
    expect(h.update).toHaveBeenCalled()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'The project was saved, but a step after the save failed',
      code: 'ECONNREFUSED',
      stage: 'after_write',
    })
  })

  test('a missing row is still a 404', async () => {
    h.update.mockRejectedValue(prismaError('P2025'))
    const res = await put(JSON.stringify({ katanaDepth: 3 }))
    expect(res.status).toBe(404)
    expect((await res.json()).error).toBe('Project not found')
  })
})
