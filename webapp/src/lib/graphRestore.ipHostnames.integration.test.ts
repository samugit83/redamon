/** @vitest-environment node */
/**
 * Hostnames on target IPs against a real Neo4j (P4, design §6.1 and §6.3):
 * an IP-mode graph with a recorded name (ExternalDomain -[:SEEN_ON]-> IP) and a
 * scanned one (org Domain {ip_hostname_org} -[:HAS_SUBDOMAIN]-> Subdomain
 * -[:RESOLVES_TO]-> IP) round-trips through restoreGraph, and the project
 * delete (clearProjectGraph, projectTeardown) leaves none of it behind.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/graphRestore.ipHostnames.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll, afterEach } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { clearProjectGraph, restoreGraph, type RestorableNode } from './graphRestore'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `RESTORE_IPHN_${Math.random().toString(36).slice(2, 10)}`
const UID = `restore-iphn-${Math.random().toString(36).slice(2, 10)}`

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    session = driver.session()
    await session.run('RETURN 1')
    alive = true
  } catch { alive = false }
})

afterEach(async () => {
  if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID })
})

afterAll(async () => {
  if (session) await session.close()
  if (driver) await driver.close()
})

const n = (labels: string[], properties: Record<string, unknown>, id: string): RestorableNode =>
  ({ labels, properties: { user_id: UID, ...properties }, _exportId: id })

const NODES = [
  n(['Domain'], { name: `ip-targets.${PID}`, ip_mode: true, is_mock: true, ip_hostname_mode: 'record_filter' }, 'root'),
  n(['Domain'], { name: 'example.test', ip_hostname_org: true }, 'org'),
  n(['Subdomain'], { name: 'app.example.test', source: 'ip_hostname_selection', ip_mode: true,
    ip_hostname_reason: 'scanned', ip_hostname_sources: ['ptr'], ip_hostname_evaluated_at: '2026-11-11T10:00:00Z' }, 'sub'),
  n(['ExternalDomain'], { domain: 'old.example.test', ip_hostname_reason: 'filter_no_match',
    ip_hostname_org: 'example.test', ips_seen: ['203.0.113.10'], sources: ['ptr'] }, 'ed'),
  n(['IP'], { address: '203.0.113.10' }, 'ip'),
]
const RELS = [
  { startExportId: 'root', endExportId: 'ed', type: 'HAS_EXTERNAL_DOMAIN', properties: {} },
  { startExportId: 'ed', endExportId: 'ip', type: 'SEEN_ON',
    properties: { sources: ['ptr'], resolves_here: false, cert_covers: false, reason: 'filter_no_match' } },
  { startExportId: 'org', endExportId: 'sub', type: 'HAS_SUBDOMAIN', properties: {} },
  { startExportId: 'sub', endExportId: 'ip', type: 'RESOLVES_TO', properties: { record_type: 'A' } },
]

describe.skipIf(!process.env.NEO4J_PASSWORD)('hostnames on target IPs in a real graph', () => {
  test('the IP-mode graph round-trips through a restore', async () => {
    if (!alive) return
    await restoreGraph(session!, NODES, RELS, { projectId: PID })
    const res = await session!.run(`
      MATCH (ed:ExternalDomain {project_id: $pid})-[r:SEEN_ON]->(i:IP {project_id: $pid})
      MATCH (d:Domain {project_id: $pid, ip_hostname_org: true})-[:HAS_SUBDOMAIN]->(s:Subdomain {project_id: $pid})
      RETURN ed.ip_hostname_reason AS reason, r.sources AS sources, d.name AS org, d.ip_mode AS orgIpMode,
             s.ip_hostname_reason AS scanned, valueType(s.ip_hostname_evaluated_at) STARTS WITH 'ZONED DATETIME' AS dt`,
    { pid: PID })
    expect(res.records).toHaveLength(1)
    const row = res.records[0]
    expect(row.get('reason')).toBe('filter_no_match')
    expect(row.get('sources')).toEqual(['ptr'])
    expect(row.get('org')).toBe('example.test')
    expect(row.get('orgIpMode')).toBeNull()
    expect(row.get('scanned')).toBe('scanned')
    expect(row.get('dt')).toBe(true)
  })

  test('the project delete leaves no ExternalDomain, SEEN_ON or org Domain', async () => {
    if (!alive) return
    await restoreGraph(session!, NODES, RELS, { projectId: PID })
    await clearProjectGraph(session!, PID)
    const left = await session!.run(`
      OPTIONAL MATCH (n {project_id: $pid}) WITH count(n) AS nodes
      OPTIONAL MATCH ()-[r:SEEN_ON]->() WHERE r.reason = 'filter_no_match' AND startNode(r).project_id = $pid
      RETURN nodes, count(r) AS seen`, { pid: PID })
    expect(left.records[0].get('nodes').toNumber()).toBe(0)
    expect(left.records[0].get('seen').toNumber()).toBe(0)
  })
})
