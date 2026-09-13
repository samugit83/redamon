/** @vitest-environment node */
/**
 * Strategy row 7 (L5): the graph-inputs route must have a Tlsx branch.
 *
 * SECTION_INPUT_MAP declares which node types the Tlsx modal OFFERS; this route
 * is what actually fetches them. It is a 27-branch if/else chain, and a tool with
 * no branch falls straight through to the `source: 'settings'` fallback -- the
 * modal then opens with zero selectable inputs while every other part of the
 * wiring looks correct. That silent fallthrough is what this row owns.
 *
 * Run: npx vitest run "src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.tlsx.test.ts"
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockGuard = vi.fn()
const mockFindUnique = vi.fn()
const mockRun = vi.fn()
const mockClose = vi.fn()

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } } }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: mockClose }),
}))

import { GET } from './route'

/** A neo4j-shaped record whose Integer-ish values expose toNumber(). */
function record(fields: Record<string, unknown>) {
  return { get: (k: string) => fields[k] }
}
function int(n: number) { return { toNumber: () => n } }

function call(toolId: string) {
  return GET({} as never, { params: Promise.resolve({ projectId: 'p1', toolId }) })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockGuard.mockResolvedValue(null)  // access allowed
  mockFindUnique.mockResolvedValue({ userId: 'u1', targetDomain: 'acme.test' })
  mockRun.mockResolvedValue({
    records: [record({
      domain: 'acme.test', subdomains: ['a.acme.test'], subCount: int(1),
      ipCount: int(3), portCount: int(7),
    })],
  })
})

describe('graph-inputs route — Tlsx branch', () => {
  test('returns graph-sourced IP and port counts, not the settings fallback', async () => {
    const body = await (await call('Tlsx')).json()
    expect(body.source).toBe('graph')
    expect(body.existing_ips_count).toBe(3)
    expect(body.existing_ports_count).toBe(7)
    expect(body.domain).toBe('acme.test')
  })

  test('reads IPs through their open Ports, the shape tlsx actually scans', async () => {
    await call('Tlsx')
    const [cypher] = mockRun.mock.calls[0] as [string, Record<string, unknown>]
    expect(cypher).toContain('HAS_PORT')
    expect(cypher).toContain('IP')
  })

  test('scopes the query to the tenant', async () => {
    await call('Tlsx')
    const [, params] = mockRun.mock.calls[0] as [string, Record<string, unknown>]
    expect(params).toEqual({ uid: 'u1', pid: 'p1' })
  })

  test('a Neo4j failure degrades to the settings fallback instead of 500', async () => {
    mockRun.mockRejectedValue(new Error('neo4j down'))
    const res = await call('Tlsx')
    expect(res.status).toBe(200)
    expect((await res.json()).source).toBe('settings')
  })

  test('control: an unwired tool DOES fall through to the settings fallback', async () => {
    // This is exactly what Tlsx looked like before the branch existed.
    const body = await (await call('NotAToolWeWired')).json()
    expect(body.source).toBe('settings')
    expect(mockRun).not.toHaveBeenCalled()
  })

  test('access denial short-circuits before any graph query', async () => {
    mockGuard.mockResolvedValue(new Response('forbidden', { status: 403 }))
    const res = await call('Tlsx')
    expect(res.status).toBe(403)
    expect(mockRun).not.toHaveBeenCalled()
  })
})
