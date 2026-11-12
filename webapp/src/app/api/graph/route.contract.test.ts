/**
 * Contract: /api/graph must keep returning exactly what it returned before the
 * Scan Timeline refactor extracted its read into lib/liveRead.ts.
 *
 * Every existing consumer (the graph canvas, the clustering, the node tables, the
 * agent's UI) reads this shape, and the version endpoint now claims to produce the
 * SAME shape — so a drift here silently breaks both at once.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ read: vi.fn(), cached: vi.fn(), setCached: vi.fn() }))

vi.mock('./liveRead', () => ({ readLiveGraph: (...a: unknown[]) => h.read(...a) }))
vi.mock('./cache', () => ({
  getCached: (...a: unknown[]) => h.cached(...a),
  setCached: (...a: unknown[]) => h.setCached(...a),
  invalidateCache: vi.fn(),
}))
vi.mock('./neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'owner' }),
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
}))

import { GET } from './route'

const PAYLOAD = {
  nodes: [{ id: '1', name: 'x.tld', type: 'Domain', properties: { name: 'x.tld' } }],
  links: [{ source: '1', target: '2', type: 'HAS_SUBDOMAIN' }],
}

beforeEach(() => {
  vi.clearAllMocks()
  h.cached.mockReturnValue(null)
  h.setCached.mockReturnValue('etag123')
  h.read.mockResolvedValue(PAYLOAD)
})

describe('GET /api/graph contract', () => {
  test('returns { nodes, links, projectId } and nothing renamed', async () => {
    const res = await GET(new NextRequest('http://x/api/graph?projectId=p1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(Object.keys(body).sort()).toEqual(['links', 'nodes', 'projectId'])
    expect(body.nodes).toEqual(PAYLOAD.nodes)
    expect(body.links).toEqual(PAYLOAD.links)
    expect(body.projectId).toBe('p1')
  })

  test('a node keeps its id/name/type/properties fields', async () => {
    const body = await (await GET(new NextRequest('http://x/api/graph?projectId=p1'))).json()
    expect(Object.keys(body.nodes[0]).sort()).toEqual(['id', 'name', 'properties', 'type'])
    expect(Object.keys(body.links[0]).sort()).toEqual(['source', 'target', 'type'])
  })

  test('caching headers are unchanged (Section 8.9: do not weaken them)', async () => {
    const res = await GET(new NextRequest('http://x/api/graph?projectId=p1'))
    expect(res.headers.get('Cache-Control')).toBe('private, no-cache')
    expect(res.headers.get('ETag')).toBe('"etag123"')
  })

  test('the ETag 304 path still works', async () => {
    h.cached.mockReturnValue({ etag: 'abc', timestamp: Date.now(), data: PAYLOAD })
    const res = await GET(new NextRequest('http://x/api/graph?projectId=p1', {
      headers: { 'if-none-match': '"abc"' },
    }))
    expect(res.status).toBe(304)
  })

  test('a cache hit returns the same shape as a miss', async () => {
    h.cached.mockReturnValue({ etag: 'abc', timestamp: Date.now(), data: PAYLOAD })
    const body = await (await GET(new NextRequest('http://x/api/graph?projectId=p1'))).json()
    expect(Object.keys(body).sort()).toEqual(['links', 'nodes', 'projectId'])
  })

  test('missing projectId is still a 400', async () => {
    expect((await GET(new NextRequest('http://x/api/graph'))).status).toBe(400)
  })
})
