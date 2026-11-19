/** @vitest-environment node */
/**
 * Secret values under the RoE (plan §10.2 rows 8 and 27) against a real agent and a real Neo4j: an
 * AI Navigator run on a project whose RoE is `no_access` calls run_cypher through the real tool
 * callback (credential, registry, secretGuard, the MCP queryGraph, the agent's /graph/exec, the
 * webapp's shaping), and no secret value with no recognisable shape ever comes back. Every query
 * below except the controls read the values in the security review that added this file.
 *
 * The person's access is a double (internalTools.test.ts covers the authorization). It seeds one
 * synthetic Secret node (the AWS documentation example key, invented values) under random ids and
 * removes it. Skipped unless both services answer:
 *   NEO4J_URI=bolt://localhost:7687 NEO4J_PASSWORD=<pw> AGENT_API_URL=http://localhost:8090 \
 *   INTERNAL_API_KEY=<key> npx vitest run --no-file-parallelism \
 *     'src/app/api/internal/navigator/tools/secrets.integration.test.ts'
 */
import { describe, test, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest'
import neo4j, { type Driver } from 'neo4j-driver'
import { NextRequest } from 'next/server'

const T = vi.hoisted(() => {
  const r = () => Math.random().toString(36).slice(2, 10)
  return { USER: `navsec-${r()}`, PROJECT: `cnavsec${r()}${r()}`.slice(0, 25) }
})
const VALUES = [
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'synthetic-secret-value-0123456789abcdef',
  'synthetic-paired-secret-fedcba9876543210',
  'https://api.example.com/reset?token=synthetic-reset-token-42',
]

vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: async () => ({ roeSensitiveDataHandling: 'no_access' }) } } }))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => (id === T.USER ? { id, status: 'active', sessionVersion: 0, role: 'standard' } : null),
}))
vi.mock('@/lib/authz/flags', async (orig) => ({ ...(await orig<typeof import('@/lib/authz/flags')>()), rbacFlags: () => ({ identity: true }) }))
const OWNER_ACCESS = { project: { id: T.PROJECT, userId: T.USER }, level: 'owner', toggles: { rawData: true }, via: 'owner' }
vi.mock('@/lib/authz/can', () => ({
  ActAsNotAllowedError: class extends Error {},
  can: async (_who: unknown, permission: string) => ({ allowed: true, permission, capabilities: new Set(), access: OWNER_ACCESS }),
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async (_s: unknown, projectId: string) => (projectId === T.PROJECT ? OWNER_ACCESS : null),
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
      `CREATE (:Secret {id: $pid + '-sec1', secret_type: 'AWS Secret Key', severity: 'critical', sample: 'AKIA***REDACTED***',
         matched_text: $m, secret_value: $sv, paired_secret: $ps, unmasked_url: $uu, user_id: $uid, project_id: $pid})`,
      { pid: T.PROJECT, uid: T.USER, m: VALUES[0], sv: VALUES[1], ps: VALUES[2], uu: VALUES[3] },
    )
    alive = true
  } catch {
    alive = false
  }
})

afterAll(async () => {
  if (driver) {
    await driver.executeQuery('MATCH (n) WHERE n.project_id = $pid DETACH DELETE n', { pid: T.PROJECT }).catch(() => {})
    await driver.close()
  }
})

beforeEach(() => {
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
})

async function cypher(query: string): Promise<{ status: number; text: string }> {
  const r = navigatorRuns().reserve({ personId: T.USER, projectId: T.PROJECT })
  if (!r.ok) throw new Error('reserve')
  const token = navigatorRuns().complete(r.runId, {
    threadId: 'cthread000000000000000001', tenantId: T.USER, actorId: null,
    login: { userId: T.USER, sessionVersion: 0, deviceSessionId: null, actAsStartId: null },
  })!
  const res = await callTool(new NextRequest('http://webapp:3000/api/internal/navigator/tools/run_cypher', {
    method: 'POST',
    headers: { 'x-internal-key': KEY, 'x-redamon-navigator': token, 'content-type': 'application/json' },
    body: JSON.stringify({ args: { cypher: query } }),
  }), { params: Promise.resolve({ name: 'run_cypher' }) })
  const text = await res.text()
  navigatorRuns().end(r.runId)
  return { status: res.status, text }
}

function noValue(text: string) {
  for (const v of VALUES) expect(text).not.toContain(v)
}

describe.runIf(PASSWORD && KEY && AGENT)('under RoE no_access no secret value comes back', () => {
  test('the whole node comes back with every secret-valued property withheld', async () => {
    if (!alive) return
    const { status, text } = await cypher('MATCH (s:Secret) RETURN s LIMIT 5')
    expect(status).toBe(200)
    expect(text).toContain('AWS Secret Key')
    expect(text).toContain('withheld')
    noValue(text)
  })

  test.each([
    ['a named property', 'MATCH (s:Secret) RETURN s.matched_text AS v LIMIT 5'],
    ['a computed key', 'MATCH (s:Secret) RETURN [k IN keys(s) | properties(s)[k]] AS v LIMIT 5'],
    ['a comment before a computed key', 'MATCH (s:Secret) RETURN [k IN keys(s) | properties(s)/**/[k]] AS v LIMIT 5'],
    ['a line comment before a computed key', 'MATCH (s:Secret) RETURN [k IN keys(s) | properties(s) //,\n[k]] AS v LIMIT 5'],
    ['a keyword-named variable', 'MATCH (s:Secret) WITH s, properties(s) AS limit RETURN [k IN keys(s) | limit[k]] AS v LIMIT 5'],
    ['escaped property names',
      'MATCH (s:Secret) RETURN s.\\u006datched_text AS a, s.\\u0073ecret_value AS b, s.\\u0070aired_secret AS c, s.\\u0075nmasked_url AS d LIMIT 5'],
  ])('%s: refused, or no value in the answer', async (_name, query) => {
    if (!alive) return
    const { status, text } = await cypher(query)
    expect([200, 400]).toContain(status)
    noValue(text)
  })
})
