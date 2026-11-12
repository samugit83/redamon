/** @vitest-environment node */
/**
 * The OpenAPI branch of graph-inputs returns, beside the BaseURL counts the
 * partial-recon modal needs, the per-source status the last runs recorded on
 * the project's Domain nodes. It is read under the same project guard, scoped
 * to the project owner and project, and a failed read degrades to "unknown"
 * instead of failing the modal.
 *
 * Run: npx vitest run "src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.openapi.test.ts"
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockGuard = vi.fn()
const mockFindUnique = vi.fn()
const mockRun = vi.fn()
const mockClose = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } } }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: mockClose }),
}))

import { GET } from './route'

function record(fields: Record<string, unknown>) {
  return { get: (k: string) => fields[k] }
}
function int(n: number) { return { toNumber: () => n } }

function call(toolId: string) {
  return GET({} as never, { params: Promise.resolve({ projectId: 'p1', toolId }) })
}

const STATUS = ['src-1|0123456789ab|ok|2026-10-19T00:00:00Z', 'src-2|ba9876543210|blocked_address|2026-10-19T00:00:00Z']

beforeEach(() => {
  vi.clearAllMocks()
  mockGuard.mockResolvedValue(null)
  mockFindUnique.mockResolvedValue({ userId: 'u1', targetDomain: 'acme.test' })
  mockRun.mockImplementation(async (cypher: string) => {
    if (cypher.includes('AS hasData')) return { records: [record({ name: 'acme.test', hasData: true })] }
    if (cypher.includes('openapi_source_status')) return { records: [record({ status: STATUS })] }
    return { records: [record({ baseurls: ['https://api.acme.test'], baseurlCount: int(1), subCount: int(0) })] }
  })
})

describe('graph-inputs route — OpenAPI branch', () => {
  test('returns the per-source status beside the BaseURL inputs', async () => {
    const body = await (await call('OpenAPI')).json()
    expect(body.source).toBe('graph')
    expect(body.openapiSourceStatus).toEqual(STATUS)
  })

  test('reads the status for the project owner and the project only', async () => {
    await call('OpenAPI')
    const [cypher, params] = mockRun.mock.calls.find(([c]) => String(c).includes('openapi_source_status')) as
      [string, Record<string, unknown>]
    expect(params).toEqual({ uid: 'u1', pid: 'p1' })
    expect(cypher).toContain('(d:Domain {user_id: $uid, project_id: $pid})')
  })

  test('a failed status read degrades to unknown, not to an error', async () => {
    mockRun.mockImplementation(async (cypher: string) => {
      if (cypher.includes('AS hasData')) return { records: [record({ name: 'acme.test', hasData: true })] }
      if (cypher.includes('openapi_source_status')) throw new Error('neo4j down')
      return { records: [record({ baseurls: [], baseurlCount: int(0) })] }
    })
    const response = await call('OpenAPI')
    expect(response.status).toBe(200)
    expect((await response.json()).openapiSourceStatus).toBeNull()
  })

  test('the project guard runs first and refuses before any graph read', async () => {
    mockGuard.mockResolvedValue(new Response('forbidden', { status: 403 }))
    const response = await call('OpenAPI')
    expect(response.status).toBe(403)
    expect(mockRun).not.toHaveBeenCalled()
  })

  test('other tools do not carry the status', async () => {
    const body = await (await call('Katana')).json()
    expect(body).not.toHaveProperty('openapiSourceStatus')
  })
})
