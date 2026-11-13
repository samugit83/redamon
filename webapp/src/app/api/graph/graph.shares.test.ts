/**
 * The graph on a shared project (step 4.6; SH-07, SH-35, NF-10, NF-11): the graph read, the saved
 * views list and a view's Cypher answer a read collaborator what they answer the owner, from the
 * owner's project (the cache entry, its ETag and the tenant filter are the project's, never the
 * reader's); every graph write and the natural-language generator (`agent:assistants`, a write
 * level that spends a key) refuse the collaborator with the 403 naming their permission, before
 * any read. Someone the project is not shared with, and anyone with sharing not in force, get 404.
 *
 * Real guard, can(), projectAccess(), readLiveGraph, the formatter and the cache; the session,
 * Prisma, the graph session and the agent are doubles (sharedReads.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), shares: new Map(), policy: { enabled: true } as unknown, models: {} as Record<string, unknown>, refused: vi.fn(),
  queries: [] as Array<{ query: string; params: unknown }>,
  sessions: [] as unknown[],
  agent: vi.fn(),
}))
// A whole-module double: session.ts imports guards.ts, so a partial one (importOriginal) would
// leave the guard holding the real getAuthzIdentity. Nobody acts as anyone here.
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
  mayActAs: async () => false,
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedReads')).sharedReadPrisma(h as never) }))

// The owner's subgraph as Neo4j answers it: two Domains, each with a Subdomain that BELONGS_TO it.
const ids = { low: 0, high: 0 }
const node = (id: number, label: string, name: string) =>
  ({ identity: { ...ids, low: id }, labels: [label], properties: { name, user_id: 'alice', project_id: 'P-alice' } })
const rel = (id: number, start: number, end: number) =>
  ({ identity: { ...ids, low: id }, start: { ...ids, low: start }, end: { ...ids, low: end }, type: 'BELONGS_TO', properties: {} })
const record = (fields: Record<string, unknown>) => ({ keys: Object.keys(fields), get: (k: string) => fields[k] })
const SUBGRAPH = [
  record({ n: node(11, 'Subdomain', 'a.one.rbac.test'), r: rel(101, 11, 1), m: node(1, 'Domain', 'one.rbac.test') }),
  record({ n: node(12, 'Subdomain', 'b.two.rbac.test'), r: rel(102, 12, 2), m: node(2, 'Domain', 'two.rbac.test') }),
]
vi.mock('@/app/api/graph/neo4j', () => ({
  neo4j: { int: (n: number) => n },
  getGraphSession: (opts?: unknown) => {
    h.sessions.push(opts ?? {})
    return {
      run: async (query: string, params?: unknown) => {
        h.queries.push({ query, params })
        return { records: /DETACH DELETE/.test(query) ? [] : SUBGRAPH }
      },
      close: async () => undefined,
    }
  },
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => h.agent(...a),
}))

import {
  COLLABORATOR, OVERSEER, OWNER, RAW_COLLABORATOR, SHARED_PROJECT, STRANGER,
  endSharedReads, mentions, resetSharedReads, setFlags, signInAs,
} from '@/lib/authz/__testing__/sharedReads'
import { invalidateCache } from './cache'
import { GET as graphGET, DELETE as graphDELETE } from './route'
import { GET as viewsGET, POST as viewsPOST } from '@/app/api/graph-views/route'
import { PUT as viewPUT, DELETE as viewDELETE } from '@/app/api/graph-views/[id]/route'
import { POST as executePOST } from '@/app/api/graph-views/execute/route'
import { POST as purgePOST } from '@/app/api/projects/[id]/purge-orphan-chains/route'
import { POST as textToCypherPOST } from '@/app/api/agent/text-to-cypher/route'

const BASE = 'http://localhost:3000'
const jsonInit = (method: string, body: unknown) => ({
  method, headers: { 'content-type': 'application/json', origin: BASE }, body: JSON.stringify(body),
})
const graphRead = (query = '', headers: Record<string, string> = {}) =>
  graphGET(new NextRequest(`${BASE}/api/graph?projectId=${SHARED_PROJECT}${query}`, { headers }))

async function callAs<T>(who: string, call: () => Promise<T>): Promise<T> {
  signInAs(h as never, who)
  h.queries.length = 0
  return call()
}

const viewRows = [{ id: 'view-1', projectId: SHARED_PROJECT, name: "the owner's view", description: '', cypherQuery: 'MATCH (d:Domain) RETURN d' }]
const viewReads: unknown[] = []
const writes = vi.fn()

beforeEach(async () => {
  await resetSharedReads(h as never)
  invalidateCache(SHARED_PROJECT)
  h.sessions.length = 0
  viewReads.length = 0
  writes.mockReset()
  h.agent.mockReset()
  h.agent.mockResolvedValue(new Response(JSON.stringify({ cypher: 'MATCH (d:Domain) RETURN d' }), { status: 200 }))
  h.models.conversation = { findMany: async () => [] }
  h.models.graphView = {
    findMany: async (args: { where: { projectId: string } }) => {
      viewReads.push(args)
      return viewRows.filter(v => v.projectId === args.where.projectId)
    },
    findUnique: async () => ({ projectId: SHARED_PROJECT }),
    create: async (...a: unknown[]) => { writes('graphView.create', ...a); return {} },
    update: async (...a: unknown[]) => { writes('graphView.update', ...a); return {} },
    delete: async (...a: unknown[]) => { writes('graphView.delete', ...a); return {} },
  }
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(async () => {
  await endSharedReads()
  vi.restoreAllMocks()
})

describe('GET /api/graph: a read collaborator gets the owner graph (step 4.6)', () => {
  test("from the cache the owner's read filled: the same nodes, links and ETag", async () => {
    const owner = await callAs(OWNER, () => graphRead())
    const reader = await callAs(COLLABORATOR, () => graphRead())
    expect(owner.status).toBe(200)
    expect(reader.status).toBe(200)
    const body = await reader.json()
    expect(body).toEqual(await owner.json())
    expect(body.nodes.map((n: { name: string }) => n.name).sort()).toEqual(['a.one.rbac.test', 'b.two.rbac.test', 'one.rbac.test', 'two.rbac.test'])
    expect(reader.headers.get('etag')).toBe(owner.headers.get('etag'))
    expect(h.queries).toEqual([])
  })

  test("on a cache miss: the graph read binds the owner's project and never the reader", async () => {
    const owner = await (await callAs(OWNER, () => graphRead('&fresh=1'))).json()
    const reader = await callAs(COLLABORATOR, () => graphRead('&fresh=1'))
    expect(reader.status).toBe(200)
    expect(await reader.json()).toEqual(owner)
    expect(h.queries.length).toBeGreaterThanOrEqual(2)
    for (const q of h.queries) {
      expect((q.params as { projectId: string }).projectId).toBe(SHARED_PROJECT)
      expect(mentions(q.params, COLLABORATOR)).toBe(false)
    }
  })

  test("the owner's ETag answers 304 to the reader: one view of the graph in this step (4.9 gives a stripped view its own)", async () => {
    const etag = (await callAs(OWNER, () => graphRead())).headers.get('etag')!
    const res = await callAs(COLLABORATOR, () => graphRead('', { 'if-none-match': etag }))
    expect(res.status).toBe(304)
    expect(res.headers.get('etag')).toBe(etag)
  })

  test('a collaborator with Raw data & files and an overseer read the same graph', async () => {
    const owner = await (await callAs(OWNER, () => graphRead('&fresh=1'))).json()
    for (const who of [RAW_COLLABORATOR, OVERSEER]) {
      const res = await callAs(who, () => graphRead('&fresh=1'))
      expect([who, res.status]).toEqual([who, 200])
      expect(await res.json()).toEqual(owner)
    }
  })

  test('someone the project is not shared with: 404 before any read', async () => {
    const res = await callAs(STRANGER, () => graphRead('&fresh=1'))
    expect(res.status).toBe(404)
    expect(h.queries).toEqual([])
  })

  test.each([
    ['the sharing switch off', () => setFlags({ identity: true, permissions: true, sharing: false })],
    ['the policy disabled', async () => { h.policy = {}; await setFlags({ identity: true, permissions: true, sharing: true }) }],
  ])('%s: the collaborator gets 404, the owner the same graph', async (_state, turnOff) => {
    const before = await (await callAs(OWNER, () => graphRead('&fresh=1'))).json()
    await turnOff()
    const reader = await callAs(COLLABORATOR, () => graphRead())
    expect(reader.status).toBe(404)
    const owner = await callAs(OWNER, () => graphRead('&fresh=1'))
    expect(await owner.json()).toEqual(before)
  })
})

describe('the saved views and their Cypher on a shared project', () => {
  test("GET /api/graph-views: the collaborator lists the owner's views of the project", async () => {
    const owner = await callAs(OWNER, () => viewsGET(new NextRequest(`${BASE}/api/graph-views?projectId=${SHARED_PROJECT}`)))
    const reader = await callAs(COLLABORATOR, () => viewsGET(new NextRequest(`${BASE}/api/graph-views?projectId=${SHARED_PROJECT}`)))
    expect(reader.status).toBe(200)
    expect(await reader.json()).toEqual(await owner.json())
    expect(viewReads).toEqual([{ where: { projectId: SHARED_PROJECT }, orderBy: { createdAt: 'desc' } }, { where: { projectId: SHARED_PROJECT }, orderBy: { createdAt: 'desc' } }])
  })

  test("POST /api/graph-views/execute: the collaborator runs a read-only view on the owner's project and gets the owner's answer", async () => {
    const run = () => executePOST(new NextRequest(`${BASE}/api/graph-views/execute`,
      jsonInit('POST', { projectId: SHARED_PROJECT, cypherQuery: 'MATCH (d:Domain) RETURN d' })))
    const owner = await callAs(OWNER, run)
    const ownerQueries = [...h.queries]
    const reader = await callAs(COLLABORATOR, run)
    expect(reader.status).toBe(200)
    expect(await reader.json()).toEqual(await owner.json())
    expect(h.queries).toEqual(ownerQueries)
    expect(h.queries).toHaveLength(1)
    expect(h.queries[0].params).toEqual({ projectId: SHARED_PROJECT })
    expect(h.queries[0].query).toContain('project_id: $projectId')
  })

  test('a view that writes is still refused for the collaborator, as for the owner (400, nothing run)', async () => {
    const res = await callAs(COLLABORATOR, () => executePOST(new NextRequest(`${BASE}/api/graph-views/execute`,
      jsonInit('POST', { projectId: SHARED_PROJECT, cypherQuery: 'MATCH (d:Domain) DETACH DELETE d' }))))
    expect(res.status).toBe(400)
    expect(h.queries).toEqual([])
  })

  test("the 4.3 review's bypass (a write behind a string holding //) is refused for every reader and the owner; views run read-only", async () => {
    const bypass = "MATCH (n) WHERE n.url <> 'http://x' DETACH DELETE n"
    for (const who of [COLLABORATOR, RAW_COLLABORATOR, OVERSEER, OWNER]) {
      h.sessions.length = 0
      const res = await callAs(who, () => executePOST(new NextRequest(`${BASE}/api/graph-views/execute`,
        jsonInit('POST', { projectId: SHARED_PROJECT, cypherQuery: bypass }))))
      expect([who, res.status]).toEqual([who, 400])
      expect(h.queries).toEqual([])
      expect(h.sessions).toEqual([])
    }
    await callAs(COLLABORATOR, () => executePOST(new NextRequest(`${BASE}/api/graph-views/execute`,
      jsonInit('POST', { projectId: SHARED_PROJECT, cypherQuery: 'MATCH (d:Domain) RETURN d' }))))
    expect(h.sessions).toEqual([{ readOnly: true }])
  })
})

describe('graph writes and the generator refuse a read collaborator (403 naming the permission, nothing read or written)', () => {
  const CASES: Array<[string, string, () => Promise<Response>]> = [
    ['DELETE /api/graph', 'graph:edit', () => graphDELETE(new NextRequest(`${BASE}/api/graph?projectId=${SHARED_PROJECT}&nodeId=11`, { method: 'DELETE', headers: { origin: BASE } }))],
    ['POST /api/graph-views', 'graph:views', () => viewsPOST(new NextRequest(`${BASE}/api/graph-views`, jsonInit('POST', { projectId: SHARED_PROJECT, name: 'mine', cypherQuery: 'MATCH (d:Domain) RETURN d' })))],
    ['PUT /api/graph-views/[id]', 'graph:views', () => viewPUT(new NextRequest(`${BASE}/api/graph-views/view-1`, jsonInit('PUT', { name: 'renamed' })), { params: Promise.resolve({ id: 'view-1' }) })],
    ['DELETE /api/graph-views/[id]', 'graph:views', () => viewDELETE(new NextRequest(`${BASE}/api/graph-views/view-1`, { method: 'DELETE', headers: { origin: BASE } }), { params: Promise.resolve({ id: 'view-1' }) })],
    ['POST /api/projects/[id]/purge-orphan-chains', 'graph:edit', () => purgePOST(new NextRequest(`${BASE}/api/projects/${SHARED_PROJECT}/purge-orphan-chains`, { method: 'POST', headers: { origin: BASE } }), { params: Promise.resolve({ id: SHARED_PROJECT }) })],
    ['POST /api/agent/text-to-cypher', 'agent:assistants', () => textToCypherPOST(new NextRequest(`${BASE}/api/agent/text-to-cypher`, jsonInit('POST', { question: 'list domains', project_id: SHARED_PROJECT })))],
  ]

  test.each(CASES)('%s refuses %s', async (_route, permission, call) => {
    for (const who of [COLLABORATOR, RAW_COLLABORATOR, OVERSEER]) {
      const res = await callAs(who, call)
      expect([who, res.status]).toEqual([who, 403])
      expect(await res.json()).toMatchObject({ code: 'forbidden', permission })
    }
    expect(h.queries).toEqual([])
    expect(writes).not.toHaveBeenCalled()
    expect(h.agent).not.toHaveBeenCalled()
  })

  test("the owner's question names the owner as the graph tenant and the key owner (NF-11)", async () => {
    const res = await callAs(OWNER, () => textToCypherPOST(new NextRequest(`${BASE}/api/agent/text-to-cypher`,
      jsonInit('POST', { question: 'list domains', project_id: SHARED_PROJECT, user_id: COLLABORATOR, tenant_user_id: COLLABORATOR }))))
    expect(res.status).toBe(200)
    const [path, init] = h.agent.mock.calls[0] as [string, { body: string }]
    expect(path).toBe('/text-to-cypher')
    expect(JSON.parse(init.body)).toMatchObject({ user_id: OWNER, tenant_user_id: OWNER, project_id: SHARED_PROJECT, question: 'list domains' })
  })
})
