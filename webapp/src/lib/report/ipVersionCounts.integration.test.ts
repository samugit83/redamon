/** @vitest-environment node */
/**
 * Real Neo4j: the report and Insights count an IP-mode node's 'v4' / 'v6'
 * spelling of IP.version beside the 'ipv4' / 'ipv6' every other writer uses.
 * The unit test (ipVersionCounts.test.ts) checks the query text; this runs it.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/report/ipVersionCounts.integration.test.ts'
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
const PID = `IP_VERSION_${Math.random().toString(36).slice(2, 10)}`
const UID = `ip-version-${Math.random().toString(36).slice(2, 10)}`

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
    `UNWIND $rows AS row
     CREATE (:IP {address: row.address, version: row.version, user_id: $uid, project_id: $pid})`,
    {
      uid: UID, pid: PID,
      rows: [
        { address: '192.0.2.10', version: 'v4' },
        { address: '192.0.2.11', version: 'v4' },
        { address: '198.51.100.7', version: 'ipv4' },
        { address: '2001:db8::10', version: 'v6' },
        { address: '2001:db8::11', version: 'ipv6' },
      ],
    },
  )
})

afterAll(async () => {
  if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID })
  if (session) await session.close()
  if (driver) await driver.close()
})

describe('IPv4 / IPv6 counts over both spellings', () => {
  test('the report', async (ctx) => {
    if (!alive || !session) ctx.skip()
    const overview = await queryGraphOverview(session, PID)
    expect(overview.infrastructureStats).toMatchObject({ totalIps: 5, ipv4: 3, ipv6: 2 })
  })

  test('Insights graph overview', async (ctx) => {
    if (!alive || !session) ctx.skip()
    const request = { nextUrl: new URL(`http://localhost:3000/api/analytics/graph-overview?projectId=${PID}`) }
    const body = await (await graphOverview.GET(request as never)).json()
    expect(body.infrastructureStats).toMatchObject({ totalIps: 5, ipv4: 3, ipv6: 2 })
  })
})
