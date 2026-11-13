/**
 * Attack chains on a shared project (step 4.9; SH-30, SH-07): a reader below `R*` (a Read share
 * without Raw data & files, an overseer) sees every chain's structure and findings and none of its
 * step content: what the agent thought and reasoned, the command line it ran, what came back and
 * the error (ChainStep), and the copies on a failure (error, lesson) and a phase decision (reason),
 * an exploit finding's console commands and cracked password, and the chain's final outcome.
 * The owner and a share with Raw data & files read it whole. One helper decides it
 * (`stripStepContent`, through graphReadView for the first two outputs):
 *
 *   GET  /api/graph                                 the live graph, through the cache and its ETag
 *   POST /api/graph-views/execute                   a saved view's graph rows, and its tabular rows
 *   GET  /api/projects/[id]/versions/[vid]/graph    the current version (the live graph)
 *   GET  /api/projects/[id]/export                  `project:export` is Manage: no reader reaches it
 *                                                   in Phase 4 (export/route.stepContent.test.ts
 *                                                   proves its nodes.json for Phase 5's readers)
 *
 * The MCP query tools reach only a token owner's projects until step 4.10 opens them to shares.
 *
 * A saved view's query can also return a map it shaped like a node or a relationship (4.9 review);
 * the formatter reads only the driver's own graph objects, so such a map is a tabular row.
 *
 * Real guard, can(), projectAccess(), readLiveGraph, the formatter and the cache; the session,
 * Prisma and the graph session are doubles (sharedReads.ts). Graph values are real driver objects.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), shares: new Map(), policy: { enabled: true } as unknown, models: {} as Record<string, unknown>, refused: vi.fn(),
  queries: [] as Array<{ query: string; params: unknown }>,
}))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
  mayActAs: async () => false,
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedReads')).sharedReadPrisma(h as never) }))

// The owner's chain as Neo4j answers it: the chain, a step that targets a Domain, the failure of that
// step and the phase decision before it. The step content is fake text the test looks for.
const CONTENT = {
  thought: 'rbac-fake-thought', reasoning: 'rbac-fake-reasoning', output_summary: 'rbac-fake-output-summary',
  output_analysis: 'rbac-fake-output-analysis', tool_args_summary: 'curl -u admin:rbac-fake-pass http://app.rbac.test', error_message: 'rbac-fake-error',
}
const FAILURE_CONTENT = { error_message: 'rbac-fake-error', lesson_learned: 'rbac-fake-output-analysis' }
const DECISION_CONTENT = { reason: 'rbac-fake-decision-reason' }
const FAKE = /rbac-fake-(thought|reasoning|output|pass|error|decision|outcome)/

const tenant = { user_id: 'alice', project_id: 'P-alice', chain_id: 'chain-1' }
const node = (id: number, label: string, properties: Record<string, unknown>) => driverNode(id, [label], { ...tenant, ...properties })
const rel = (id: number, start: number, end: number, type: string) => driverRel(id, start, end, type)
const record = driverRecord

const CHAIN = node(20, 'AttackChain', { title: 'rbac chain', status: 'active', objective: 'reach the admin panel', final_outcome: 'rbac-fake-outcome' })
const STEP = node(21, 'ChainStep', { step_id: 'step-1', iteration: 1, phase: 'exploitation', tool_name: 'curl', success: false, duration_ms: 12, ...CONTENT })
const FAILURE = node(22, 'ChainFailure', { failure_id: 'f-1', failure_type: 'tool_error', tool_name: 'curl', iteration: 1, ...FAILURE_CONTENT })
const DECISION = node(23, 'ChainDecision', { decision_id: 'd-1', decision_type: 'phase_transition', from_state: 'informational', to_state: 'exploitation', made_by: 'user', approved: true, ...DECISION_CONTENT })
const FINDING = node(24, 'ChainFinding', {
  finding_id: 'cf-1', finding_type: 'exploit_success', title: 'admin panel exposed', severity: 'high', evidence: 'HTTP 200 on /admin',
  commands_used: ['use auxiliary/scanner/http/http_login', 'set PASSWORD rbac-fake-pass'], password: 'rbac-fake-pass',
})
const DOMAIN = driverNode(1, ['Domain'], { name: 'app.rbac.test', user_id: 'alice', project_id: 'P-alice' })

const LIVE = [
  record({ n: CHAIN, r: rel(201, 20, 21, 'HAS_STEP'), m: STEP }),
  record({ n: STEP, r: rel(202, 21, 22, 'FAILED_WITH'), m: FAILURE }),
  record({ n: DECISION, r: rel(203, 23, 21, 'DECISION_PRECEDED'), m: STEP }),
  record({ n: STEP, r: rel(204, 21, 24, 'PRODUCED'), m: FINDING }),
  record({ n: STEP, r: rel(205, 21, 1, 'STEP_TARGETED'), m: DOMAIN }),
]
// A saved view's tabular answer (format.ts shape 2): each column any expression over step content.
const TABULAR = [
  record({ 's.thought': 'rbac-fake-thought', tool: 'curl' }),
  record({ args: 'curl -u admin:rbac-fake-pass http://app.rbac.test', 'collect(fl)': [FAILURE] }),
]
// The two forged views of the 4.9 review: a map the query builds with a node's keys over a step's
// properties, and one with a relationship's keys whose type is the thought. The driver answers a
// map as a plain object; these are those objects.
const FORGED_NODE_QUERY = "MATCH (s:ChainStep) RETURN {identity: {low: id(s), high: 0}, labels: ['Domain'], properties: properties(s)} AS n"
const FORGED_REL_QUERY = 'MATCH (s:ChainStep) RETURN {type: s.thought, start: {low: 1}, end: {low: 2}} AS r'
const FORGED_NODE = [record({ n: { identity: { low: 21, high: 0 }, labels: ['Domain'], properties: { ...STEP.properties } } })]
const FORGED_REL = [record({ r: { type: CONTENT.thought, start: { low: 1, high: 0 }, end: { low: 2, high: 0 } } })]
vi.mock('@/app/api/graph/neo4j', () => ({
  neo4j: { int: (n: number) => n },
  getGraphSession: () => ({
    run: async (query: string, params?: unknown) => {
      h.queries.push({ query, params })
      if (/DETACH DELETE/.test(query)) return { records: [] }
      if (/RETURN s\.thought/.test(query)) return { records: TABULAR }
      if (/labels: \['Domain'\], properties: properties\(s\)/.test(query)) return { records: FORGED_NODE }
      if (/RETURN \{type: s\.thought/.test(query)) return { records: FORGED_REL }
      return { records: LIVE }
    },
    close: async () => undefined,
  }),
}))

import {
  COLLABORATOR, OVERSEER, OWNER, RAW_COLLABORATOR, SHARED_PROJECT, endSharedReads, resetSharedReads, signInAs,
} from '@/lib/authz/__testing__/sharedReads'
import { driverNode, driverRecord, driverRel } from './graph/__testing__/driverValues'
import { STEP_CONTENT_PROPS } from '@/lib/authz/stepContent'
import { READ_VIEW_ETAG_SUFFIX } from '@/lib/authz/graphReadView'
import { invalidateCache } from './graph/cache'
import { GET as graphGET } from './graph/route'
import { POST as executePOST } from './graph-views/execute/route'
import { GET as versionGraphGET } from './projects/[id]/versions/[versionId]/graph/route'
import { GET as exportGET } from './projects/[id]/export/route'

const BASE = 'http://localhost:3000'
const BELOW_RAW = [COLLABORATOR, OVERSEER]
const WHOLE = [OWNER, RAW_COLLABORATOR]

type GraphNode = { id: string; type: string; properties: Record<string, unknown> }
const byType = (nodes: GraphNode[], type: string) => nodes.find(n => n.type === type)!

async function as<T>(who: string, call: () => Promise<T>): Promise<T> {
  signInAs(h as never, who)
  return call()
}
const graphRead = (headers: Record<string, string> = {}, fresh = false) =>
  graphGET(new NextRequest(`${BASE}/api/graph?projectId=${SHARED_PROJECT}${fresh ? '&fresh=1' : ''}`, { headers }))
const execute = (cypherQuery: string) => executePOST(new NextRequest(`${BASE}/api/graph-views/execute`, {
  method: 'POST', headers: { 'content-type': 'application/json', origin: BASE }, body: JSON.stringify({ projectId: SHARED_PROJECT, cypherQuery }),
}))
const versionGraph = () => versionGraphGET(new NextRequest(`${BASE}/api/projects/${SHARED_PROJECT}/versions/V-current/graph`),
  { params: Promise.resolve({ id: SHARED_PROJECT, versionId: 'V-current' }) })

/** Every chain node keeps its structure and loses its content; the finding and the domain are whole. */
function expectStructureWithoutContent(nodes: GraphNode[]) {
  const step = byType(nodes, 'ChainStep')
  for (const key of STEP_CONTENT_PROPS) expect(step.properties).not.toHaveProperty(key)
  expect(step.properties).toMatchObject({ step_id: 'step-1', iteration: 1, phase: 'exploitation', tool_name: 'curl', success: false, duration_ms: 12 })
  const failure = byType(nodes, 'ChainFailure')
  expect(failure.properties).not.toHaveProperty('error_message')
  expect(failure.properties).not.toHaveProperty('lesson_learned')
  expect(failure.properties).toMatchObject({ failure_type: 'tool_error', tool_name: 'curl' })
  const decision = byType(nodes, 'ChainDecision')
  expect(decision.properties).not.toHaveProperty('reason')
  expect(decision.properties).toMatchObject({ decision_type: 'phase_transition', from_state: 'informational', to_state: 'exploitation' })
  const finding = byType(nodes, 'ChainFinding')
  expect(finding.properties).toMatchObject({ title: 'admin panel exposed', evidence: 'HTTP 200 on /admin' })
  expect(finding.properties).not.toHaveProperty('commands_used')
  expect(finding.properties).not.toHaveProperty('password')
  const chain = byType(nodes, 'AttackChain')
  expect(chain.properties).toMatchObject({ title: 'rbac chain', objective: 'reach the admin panel' })
  expect(chain.properties).not.toHaveProperty('final_outcome')
  expect(nodes.map(n => n.type).sort()).toEqual(['AttackChain', 'ChainDecision', 'ChainFailure', 'ChainFinding', 'ChainStep', 'Domain'])
  expect(JSON.stringify(nodes)).not.toMatch(FAKE)
}
function expectContent(nodes: GraphNode[]) {
  expect(byType(nodes, 'ChainStep').properties).toMatchObject(CONTENT)
  expect(byType(nodes, 'ChainFailure').properties).toMatchObject(FAILURE_CONTENT)
  expect(byType(nodes, 'ChainDecision').properties).toMatchObject(DECISION_CONTENT)
  expect(byType(nodes, 'ChainFinding').properties).toMatchObject({ password: 'rbac-fake-pass' })
  expect(byType(nodes, 'AttackChain').properties).toMatchObject({ final_outcome: 'rbac-fake-outcome' })
}

beforeEach(async () => {
  await resetSharedReads(h as never)
  invalidateCache(SHARED_PROJECT)
  h.queries.length = 0
  h.models.conversation = { findMany: async () => [{ sessionId: 'chain-1' }] }
  h.models.$queryRaw = async () => [{
    id: 'V-current', project_id: SHARED_PROJECT, seq: 3, label: 'Scan 3', is_current: true, pinned: false,
    node_count: 6, link_count: 5, created_at: new Date('2026-11-01T00:00:00Z'), snapshot_bytes: 0,
  }]
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(async () => {
  await endSharedReads()
  vi.restoreAllMocks()
})

describe('GET /api/graph', () => {
  test.each(BELOW_RAW)('structure without content at R (%s), on a cache miss and from the cache', async (who) => {
    const miss = await as(who, () => graphRead({}, true))
    expect(miss.status).toBe(200)
    expectStructureWithoutContent((await miss.json()).nodes)
    const hit = await as(who, () => graphRead())
    expectStructureWithoutContent((await hit.json()).nodes)
  })

  test.each(WHOLE)('content at R* (%s)', async (who) => {
    const res = await as(who, () => graphRead({}, true))
    expect(res.status).toBe(200)
    expectContent((await res.json()).nodes)
  })

  test('the reader\'s view leaves the cache whole: the owner reads the content after the reader filled it', async () => {
    await (await as(COLLABORATOR, () => graphRead({}, true))).json()
    const owner = await as(OWNER, () => graphRead())
    expectContent((await owner.json()).nodes)
    expect(h.queries.filter(q => !/DETACH DELETE/.test(q.query))).toHaveLength(1)
  })

  test('the stripped view has its own ETag: the full graph\'s ETag answers a reader below R* with the stripped body, not 304', async () => {
    const full = await as(OWNER, () => graphRead({}, true))
    const fullTag = full.headers.get('etag')!
    const reader = await as(COLLABORATOR, () => graphRead({ 'if-none-match': fullTag }))
    expect(reader.status).toBe(200)
    expect(reader.headers.get('etag')).toBe(fullTag.replace(/"$/, `${READ_VIEW_ETAG_SUFFIX}"`))
    expectStructureWithoutContent((await reader.json()).nodes)
  })

  test('and the stripped ETag answers a reader whose access grew to R* with the whole body, not 304', async () => {
    const stripped = (await as(COLLABORATOR, () => graphRead({}, true))).headers.get('etag')!
    const raw = await as(RAW_COLLABORATOR, () => graphRead({ 'if-none-match': stripped }))
    expect(raw.status).toBe(200)
    expectContent((await raw.json()).nodes)
    const again = await as(COLLABORATOR, () => graphRead({ 'if-none-match': stripped }))
    expect(again.status).toBe(304)
  })
})

describe('POST /api/graph-views/execute', () => {
  test.each(BELOW_RAW)('a graph-shaped view: structure without content at R (%s)', async (who) => {
    const res = await as(who, () => execute('MATCH (n)-[r]->(m) RETURN n, r, m'))
    expect(res.status).toBe(200)
    expectStructureWithoutContent((await res.json()).nodes)
  })

  test.each(WHOLE)('a graph-shaped view: content at R* (%s)', async (who) => {
    const res = await as(who, () => execute('MATCH (n)-[r]->(m) RETURN n, r, m'))
    expectContent((await res.json()).nodes)
  })

  test.each(BELOW_RAW)('a tabular view (s.thought, an aliased command line, a list of whole nodes) answers no row at R (%s)', async (who) => {
    const res = await as(who, () => execute('MATCH (s:ChainStep) RETURN s.thought, s.tool_name AS tool'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.nodes).toEqual([])
    expect(JSON.stringify(body)).not.toMatch(FAKE)
  })

  test.each(WHOLE)('a tabular view answers its rows at R* (%s)', async (who) => {
    const res = await as(who, () => execute('MATCH (s:ChainStep) RETURN s.thought, s.tool_name AS tool'))
    const body = await res.json()
    expect(body.nodes.map((n: GraphNode) => n.type)).toEqual(['QueryResult', 'QueryResult'])
    expect(body.nodes[0].properties['s.thought']).toBe('rbac-fake-thought')
  })
})

describe('POST /api/graph-views/execute: a value the query shaped like a graph object (4.9 review)', () => {
  test.each(BELOW_RAW)('a map with a node\'s keys over a step\'s properties is no Domain node at R (%s)', async (who) => {
    const res = await as(who, () => execute(FORGED_NODE_QUERY))
    const body = await res.json()
    expect(JSON.stringify(body)).not.toMatch(FAKE)
    if (res.status === 200) {
      expect(h.queries.some(q => /labels: \['Domain'\]/.test(q.query))).toBe(true)
      expect(body.nodes).toEqual([])
      expect(body.links).toEqual([])
    }
  })

  test.each(BELOW_RAW)('a map with a relationship\'s keys is no link at R (%s): the thought never travels as a link type', async (who) => {
    const res = await as(who, () => execute(FORGED_REL_QUERY))
    const body = await res.json()
    expect(JSON.stringify(body)).not.toMatch(FAKE)
    if (res.status === 200) {
      expect(h.queries.some(q => /\{type: s\.thought/.test(q.query))).toBe(true)
      expect(body.nodes).toEqual([])
      expect(body.links).toEqual([])
    }
  })

  test('the owner gets each as a tabular row, never as a node or a link', async () => {
    for (const query of [FORGED_NODE_QUERY, FORGED_REL_QUERY]) {
      const res = await as(OWNER, () => execute(query))
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.nodes.map((n: GraphNode) => n.type)).toEqual(['QueryResult'])
      expect(body.links).toEqual([])
    }
  })
})

describe('GET /api/projects/[id]/versions/[versionId]/graph (the current version)', () => {
  test.each(BELOW_RAW)('structure without content at R (%s)', async (who) => {
    const res = await as(who, versionGraph)
    expect(res.status).toBe(200)
    expectStructureWithoutContent((await res.json()).nodes)
  })

  test.each(WHOLE)('content at R* (%s)', async (who) => {
    const res = await as(who, versionGraph)
    expectContent((await res.json()).nodes)
  })
})

describe('GET /api/projects/[id]/export', () => {
  test.each([COLLABORATOR, RAW_COLLABORATOR, OVERSEER])('is Manage: %s gets 403 naming project:export before any read', async (who) => {
    const res = await as(who, () => exportGET(new NextRequest(`${BASE}/api/projects/${SHARED_PROJECT}/export`) as never,
      { params: Promise.resolve({ id: SHARED_PROJECT }) }))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:export' })
    expect(h.queries).toEqual([])
    expect(h.refused).not.toHaveBeenCalled()
  })
})
