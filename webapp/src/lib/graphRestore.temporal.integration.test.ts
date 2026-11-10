/** @vitest-environment node */
/**
 * R-38 against a real Neo4j: a restored finding's `updated_at` is a DateTime
 * again, so the recon prune's `n.updated_at < datetime($since)` can match it.
 *
 * Skipped unless a Neo4j answers. To run it against the dev stack:
 *   docker run --rm --network redamon-network -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/graphRestore.temporal.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll, afterEach } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { restoreGraph } from './graphRestore'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `RESTORE_R38_${Math.random().toString(36).slice(2, 10)}`
const UID = `restore-r38-${Math.random().toString(36).slice(2, 10)}`

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

describe.skipIf(!process.env.NEO4J_PASSWORD)('restoreGraph — timestamps (R-38)', () => {
  test('an exported updated_at is stored as a DateTime the prune can compare', async () => {
    if (!alive) return
    await restoreGraph(session!, [{
      labels: ['Vulnerability'], _exportId: 'v1',
      properties: {
        id: 'r38-v1', user_id: UID, source: 'nuclei',
        updated_at: '2026-01-02T03:04:05Z', discovered_at: '2026-01-02T03:04:05Z',
      },
    }], [], { projectId: PID })
    const res = await session!.run(
      `MATCH (v:Vulnerability {id: 'r38-v1', project_id: $pid})
       RETURN v.updated_at IS :: ZONED DATETIME AS native,
              v.updated_at < datetime('2026-06-01T00:00:00Z') AS older,
              v.discovered_at IS :: STRING AS discovered_text`,
      { pid: PID })
    const row = res.records[0]
    expect(row.get('native')).toBe(true)
    expect(row.get('older')).toBe(true)
    expect(row.get('discovered_text')).toBe(true)
  })
})
