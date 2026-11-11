/** @vitest-environment node */
/**
 * LIVE_GRAPH_QUERY against a real Neo4j: a nuclei finding's CVE chain,
 * (v:Vulnerability)-[:INCLUDES_CVE]->(c:CVE)-[:HAS_CWE]->(m:MitreData)-[:HAS_CAPEC]->(cap:Capec),
 * reaches the graph screen; a muted finding's chain and another project's do not.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network redamon-network -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/app/api/graph/liveRead.cveChain.integration.test.ts'
 *
 * Everything is scoped to two throwaway projects plus CVE / MitreData / Capec
 * reference nodes with ids in a year no real CVE uses; all are deleted after each test.
 */
import { describe, test, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'

// Only the query text is under test: keep the module's shared driver and
// Prisma client out of it.
vi.mock('./neo4j', () => ({ getGraphSession: vi.fn(), neo4j: { int: (n: number) => n } }))
vi.mock('@/lib/prisma', () => ({ default: {} }))

import { LIVE_GRAPH_QUERY } from './liveRead'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const tag = Math.random().toString(36).slice(2, 10)
const PID = `CVECHAIN_${tag}`
const OTHER_PID = `CVECHAIN_${tag}_B`
const UID = `cvechain-${tag}`
const n = Math.floor(10000 + Math.random() * 89999)
const CITED = `CVE-1900-${n}1`
const MUTED = `CVE-1900-${n}2`
const FOREIGN = `CVE-1900-${n}3`
const CVES = [CITED, MUTED, FOREIGN]
const mitreId = (cve: string) => `${cve}-CWE-9${n}`
const capecId = (cve: string) => `CAPEC-9${n}${cve.slice(-1)}`

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
  if (!alive || !session) return
  await session.run('MATCH (x) WHERE x.project_id IN [$a, $b] DETACH DELETE x', { a: PID, b: OTHER_PID })
  await session.run('MATCH (c:CVE) WHERE c.id IN $ids DETACH DELETE c', { ids: CVES })
  await session.run('MATCH (m:MitreData) WHERE m.id IN $ids DETACH DELETE m', { ids: CVES.map(mitreId) })
  await session.run('MATCH (c:Capec) WHERE c.capec_id IN $ids DETACH DELETE c', { ids: CVES.map(capecId) })
})

afterAll(async () => {
  if (session) await session.close()
  if (driver) await driver.close()
})

/** A finding of `pid` citing `cve`, and the CVE's global CWE / CAPEC chain. */
async function seed(pid: string, vulnId: string, cve: string, muted = false) {
  await session!.run(
    `CREATE (v:Vulnerability {id: $vid, source: 'nuclei', user_id: $uid, project_id: $pid})
     ${muted ? 'SET v:Muted' : ''}
     MERGE (c:CVE {id: $cve})
     MERGE (m:MitreData {id: $mid}) SET m.cve_id = $cve, m.cwe_id = $cwe
     MERGE (cap:Capec {capec_id: $cap})
     MERGE (v)-[:INCLUDES_CVE]->(c)
     MERGE (c)-[:HAS_CWE]->(m)
     MERGE (m)-[:HAS_CAPEC]->(cap)`,
    { vid: vulnId, uid: UID, pid, cve, mid: mitreId(cve), cwe: `CWE-9${n}`, cap: capecId(cve) })
}

/** (relationship type, start key, end key) for every row the query returns. */
async function rows(pid: string) {
  const res = await session!.run(LIVE_GRAPH_QUERY, { projectId: pid, maxRecords: neo4j.int(10000) })
  const key = (x: { properties: Record<string, unknown> }) =>
    String(x.properties.capec_id ?? x.properties.id)
  return res.records.map(r => [r.get('r').type, key(r.get('n')), key(r.get('m'))].join(' '))
}

describe('the live graph read on a real Neo4j', () => {
  test("reads a finding's INCLUDES_CVE chain, not a muted finding's or another project's", async ({ skip }) => {
    if (!alive || !session) skip()
    await seed(PID, `nuclei-${tag}-1`, CITED)
    await seed(PID, `nuclei-${tag}-2`, MUTED, true)
    await seed(OTHER_PID, `nuclei-${tag}-3`, FOREIGN)

    const got = await rows(PID)

    expect(got).toEqual(expect.arrayContaining([
      `INCLUDES_CVE nuclei-${tag}-1 ${CITED}`,
      `HAS_CWE ${CITED} ${mitreId(CITED)}`,
      `HAS_CAPEC ${mitreId(CITED)} ${capecId(CITED)}`,
    ]))
    // Each edge once: the union deduplicates rows several branches return.
    expect(got.filter(r => r.includes(CITED))).toHaveLength(3)
    for (const other of [MUTED, FOREIGN]) {
      expect(got.filter(r => r.includes(other))).toEqual([])
    }
  })
})
