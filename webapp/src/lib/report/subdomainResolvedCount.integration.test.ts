/** @vitest-environment node */
/**
 * Real Neo4j: Subdomains a DNS-skipped run wrote ('unverified', no RESOLVES_TO
 * edge, has_dns_records false) are counted in the total and never as resolved,
 * in the report and in Insights (plan 08.1). The unit test
 * (subdomainResolvedCount.test.ts) checks the query text; this runs it.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/report/subdomainResolvedCount.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll, vi } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `SUB_RESOLVED_${Math.random().toString(36).slice(2, 10)}`
const UID = `sub-resolved-${Math.random().toString(36).slice(2, 10)}`

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: (cypher: string, params: Record<string, unknown>) => session!.run(cypher, params),
    close: async () => {},
  }),
}))

const { queryGraphOverview } = await import('./reportData')
const graphOverview = await import('@/app/api/analytics/graph-overview/route')

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    session = driver.session()
    await session.run('RETURN 1')
    alive = true
  } catch { alive = false }
  if (!alive) return
  await session!.run(
    `CREATE (d:Domain {name: 'example.test', user_id: $uid, project_id: $pid})
     CREATE (ip:IP {address: '192.0.2.10', version: 'ipv4', user_id: $uid, project_id: $pid})
     CREATE (www:Subdomain {name: 'www.example.test', status: 'resolved', has_dns_records: true,
                            user_id: $uid, project_id: $pid})
     CREATE (www)-[:BELONGS_TO]->(d), (d)-[:HAS_SUBDOMAIN]->(www), (www)-[:RESOLVES_TO]->(ip)
     WITH d
     UNWIND ['admin.example.test', 'dev.example.test', 'vpn.example.test'] AS name
     CREATE (s:Subdomain {name: name, status: 'unverified', has_dns_records: false,
                          user_id: $uid, project_id: $pid})
     CREATE (s)-[:BELONGS_TO]->(d), (d)-[:HAS_SUBDOMAIN]->(s)`,
    { uid: UID, pid: PID },
  )
})

afterAll(async () => {
  if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID })
  if (session) await session.close()
  if (driver) await driver.close()
})

describe('unverified subdomains are not counted as resolved', () => {
  test('the report', async (ctx) => {
    if (!alive || !session) ctx.skip()
    const overview = await queryGraphOverview(session, PID)
    expect(overview.subdomainStats).toEqual({ total: 4, resolved: 1, uniqueIps: 1 })
  })

  test('Insights graph overview', async (ctx) => {
    if (!alive || !session) ctx.skip()
    const request = { nextUrl: new URL(`http://localhost:3000/api/analytics/graph-overview?projectId=${PID}`) }
    const body = await (await graphOverview.GET(request as never)).json()
    expect(body.subdomainStats).toEqual({ total: 4, resolved: 1, uniqueIps: 1 })
  })
})
