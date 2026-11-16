/** @vitest-environment node */
/**
 * Threat row 9 (plan §10.2, §12 integration tier) against a real agent and a real Neo4j: two tenants
 * in one graph, and an AI Navigator run of tenant A calls run_cypher through the real tool callback
 * (credential, registry, the MCP queryGraph, the agent's /graph/exec with scope_query, the webapp's
 * post-validation). Every crafted query answers A's rows only, or is refused; B's names and ids
 * never appear in an answer.
 *
 * The person's access is a double (the subject here is the data path, not the authorization, which
 * internalTools.test.ts covers). It seeds only synthetic nodes under random ids and removes them.
 * Skipped unless both services answer:
 *   NEO4J_URI=bolt://localhost:7687 NEO4J_PASSWORD=<pw> AGENT_API_URL=http://localhost:8090 \
 *   INTERNAL_API_KEY=<key> npx vitest run --no-file-parallelism \
 *     'src/app/api/internal/navigator/tools/tenancy.integration.test.ts'
 */
import { describe, test, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest'
import neo4j, { type Driver } from 'neo4j-driver'
import { NextRequest } from 'next/server'

const rnd = () => Math.random().toString(36).slice(2, 10)
const T = vi.hoisted(() => {
  const r = () => Math.random().toString(36).slice(2, 10)
  return {
    A_USER: `navten-a-${r()}`, A_PROJECT: `cnavtena${r()}${r()}`.slice(0, 25),
    B_USER: `navten-b-${r()}`, B_PROJECT: `cnavtenb${r()}${r()}`.slice(0, 25),
  }
})
const A_HOST = `a-${rnd()}.navtenant.test`
const B_HOST = `b-${rnd()}.navtenant.test`
const B_SECRET = `b-only-${rnd()}`

vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: async () => ({ roeSensitiveDataHandling: 'full_access' }) } } }))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => (id === T.A_USER ? { id, status: 'active', sessionVersion: 0, role: 'standard' } : null),
}))
vi.mock('@/lib/authz/flags', async (orig) => ({ ...(await orig<typeof import('@/lib/authz/flags')>()), rbacFlags: () => ({ identity: true }) }))
const OWNER_ACCESS = { project: { id: T.A_PROJECT, userId: T.A_USER }, level: 'owner', toggles: { rawData: true }, via: 'owner' }
vi.mock('@/lib/authz/can', () => ({
  ActAsNotAllowedError: class extends Error {},
  can: async (_who: unknown, permission: string) => ({ allowed: true, permission, capabilities: new Set(), access: OWNER_ACCESS }),
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async (_s: unknown, projectId: string) => (projectId === T.A_PROJECT ? OWNER_ACCESS : null),
}))
vi.mock('@/lib/navigator/switch', () => ({ navigatorEnabled: async () => true }))
vi.mock('@/lib/authz/deviceSessions', () => ({ deviceSessionRefusal: async () => null }))
vi.mock('@/lib/authz/actAs', () => ({ actAsBindingInForce: async () => true }))
vi.mock('@/lib/activationLock', () => ({ activationBusy: async () => false }))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => {} }))

import { POST as callTool } from './[name]/route'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests } from '@/lib/navigator/runRegistry'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const PASSWORD = process.env.NEO4J_PASSWORD || ''
const KEY = process.env.INTERNAL_API_KEY || ''
const AGENT = process.env.AGENT_API_URL || ''

let driver: Driver | undefined
let alive = false

beforeAll(async () => {
  if (!PASSWORD || !KEY || !AGENT) return
  try {
    const health = await fetch(`${AGENT}/health`, { signal: AbortSignal.timeout(3000) })
    if (!health.ok) return
    driver = neo4j.driver(URI, neo4j.auth.basic(process.env.NEO4J_USER || 'neo4j', PASSWORD))
    await driver.executeQuery(
      `CREATE (:Subdomain {name: $aHost, user_id: $aUser, project_id: $aProject})
       CREATE (:Subdomain {name: $bHost, user_id: $bUser, project_id: $bProject, note: $bSecret})
       CREATE (:IP {address: '192.0.2.10', user_id: $bUser, project_id: $bProject, note: $bSecret})`,
      { aHost: A_HOST, aUser: T.A_USER, aProject: T.A_PROJECT, bHost: B_HOST, bUser: T.B_USER, bProject: T.B_PROJECT, bSecret: B_SECRET },
    )
    alive = true
  } catch {
    alive = false
  }
})

afterAll(async () => {
  if (driver) {
    await driver.executeQuery('MATCH (n) WHERE n.project_id IN $pids DETACH DELETE n', { pids: [T.A_PROJECT, T.B_PROJECT] }).catch(() => {})
    await driver.close()
  }
})

beforeEach(() => {
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
})

function runOfA(): string {
  const r = navigatorRuns().reserve({ personId: T.A_USER, projectId: T.A_PROJECT })
  if (!r.ok) throw new Error('reserve')
  return navigatorRuns().complete(r.runId, {
    threadId: 'cthread000000000000000001', tenantId: T.A_USER, actorId: null,
    login: { userId: T.A_USER, sessionVersion: 0, deviceSessionId: null, actAsStartId: null },
  })!
}

async function cypher(query: string, extra: Record<string, unknown> = {}): Promise<{ status: number; text: string }> {
  const token = runOfA()
  const res = await callTool(new NextRequest('http://webapp:3000/api/internal/navigator/tools/run_cypher', {
    method: 'POST',
    headers: { 'x-internal-key': KEY, 'x-redamon-navigator': token, 'content-type': 'application/json' },
    body: JSON.stringify({ args: { cypher: query }, ...extra }),
  }), { params: Promise.resolve({ name: 'run_cypher' }) })
  return { status: res.status, text: await res.text() }
}

/** B's values never come back, except one the query itself wrote (a refusal quotes its pattern). */
function neverB(text: string, query = '') {
  for (const leak of [B_HOST, B_SECRET, T.B_USER, T.B_PROJECT, '192.0.2.10']) {
    if (!query.includes(leak)) expect(text).not.toContain(leak)
  }
}

describe.runIf(PASSWORD && KEY && AGENT)('a run of tenant A never reads tenant B', () => {
  test('the plain query answers A\'s rows only', async () => {
    if (!alive) return
    const { status, text } = await cypher('MATCH (s:Subdomain) RETURN s.name AS name LIMIT 50')
    expect(status).toBe(200)
    expect(text).toContain(A_HOST)
    neverB(text)
  })

  test.each([
    ['naming B\'s tenant in a WHERE', `MATCH (s:Subdomain) WHERE s.project_id = '${'$'}{B}' RETURN s LIMIT 50`],
    ['naming B\'s tenant in a pattern', `MATCH (s:Subdomain {project_id: '${'$'}{B}'}) RETURN s.name, s.note LIMIT 50`],
    ['an OR that would widen the filter', `MATCH (s:Subdomain) WHERE s.name = 'x' OR true RETURN s.name, s.note LIMIT 50`],
    ['a second, unlabelled pattern', 'MATCH (s:Subdomain) MATCH (n) RETURN n LIMIT 50'],
    ['a bare node scan', 'MATCH (n) RETURN n LIMIT 50'],
    ['a UNION into another label', 'MATCH (s:Subdomain) RETURN s.name AS v LIMIT 50 UNION MATCH (i:IP) RETURN i.note AS v LIMIT 50'],
    ['a CALL subquery', 'CALL { MATCH (i:IP) RETURN i } RETURN i.note LIMIT 50'],
    ['a procedure', 'CALL db.labels() YIELD label RETURN label'],
    ['LOAD CSV', "LOAD CSV FROM 'http://192.0.2.1/x.csv' AS row RETURN row LIMIT 1"],
    ['a write', `MATCH (s:Subdomain) SET s.note = 'x' RETURN s LIMIT 1`],
  ])('%s: refused, or A\'s rows only', async (_name, raw) => {
    if (!alive) return
    const query = raw.replaceAll('${B}', T.B_PROJECT)
    const { status, text } = await cypher(query)
    expect([200, 400, 403]).toContain(status)
    neverB(text, query)
  })

  test('a project or person in the body is ignored: the run\'s tenant answers', async () => {
    if (!alive) return
    const { status, text } = await cypher('MATCH (s:Subdomain) RETURN s.name AS name LIMIT 50', { projectId: T.B_PROJECT, userId: T.B_USER })
    expect(status).toBe(200)
    expect(text).toContain(A_HOST)
    neverB(text)
  })
})
