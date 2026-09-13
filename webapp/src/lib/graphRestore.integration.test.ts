/** @vitest-environment node */
/**
 * Strategy row 10 (L4, real Neo4j): activating a PRE-MIGRATION scan version must
 * not collapse its certificates.
 *
 * This is the sharpest edge in the whole feature. Snapshots are frozen bytes in
 * Postgres, so no Neo4j migration ever rewrites them: a version captured before
 * the cert_key re-key contains Certificate nodes with NO cert_key. restoreGraph
 * reads the uniqueness keys LIVE from the database, so it would MERGE every one
 * of those certificates on `{cert_key: null, user_id, project_id}` -- collapsing
 * the project's entire certificate history into a single node, or throwing
 * IndexEntryConflict. Activation is destructive-then-restore, so the live graph
 * is already gone when that happens. The loss is irreversible.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/graphRestore.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll, afterEach } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { restoreGraph, type RestorableNode } from './graphRestore'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `RESTORE_TLSX_${Math.random().toString(36).slice(2, 10)}`
const UID = `restore-tlsx-${Math.random().toString(36).slice(2, 10)}`

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

/** Two DISTINCT certificates as a pre-re-key snapshot stored them: no cert_key. */
function preMigrationCerts(): RestorableNode[] {
  return [
    {
      labels: ['Certificate'], _exportId: 'c1',
      properties: {
        user_id: UID,
        subject_cn: 'mail.acme.test', issuer: 'CN=R3',
        not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z',
      },
    },
    {
      labels: ['Certificate'], _exportId: 'c2',
      properties: {
        user_id: UID,
        subject_cn: 'imap.acme.test', issuer: 'CN=R3',
        not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z',
      },
    },
  ]
}

describe.skipIf(!process.env.NEO4J_PASSWORD)('restoreGraph — pre-migration certificates', () => {
  test('two distinct pre-migration certificates restore as two nodes', async () => {
    if (!alive) return
    await restoreGraph(session!, preMigrationCerts(), [], { projectId: PID })
    const res = await session!.run(
      'MATCH (c:Certificate {project_id: $pid}) RETURN count(c) AS n', { pid: PID })
    expect(res.records[0].get('n').toNumber()).toBe(2)
  })

  test('each restored certificate is given a derived cert_key', async () => {
    if (!alive) return
    await restoreGraph(session!, preMigrationCerts(), [], { projectId: PID })
    const res = await session!.run(
      'MATCH (c:Certificate {project_id: $pid}) RETURN collect(c.cert_key) AS keys', { pid: PID })
    const keys: (string | null)[] = res.records[0].get('keys')
    expect(keys.filter(k => k)).toHaveLength(2)
    expect(new Set(keys).size).toBe(2)   // distinct certs keep distinct identities
    for (const k of keys) expect(k).toMatch(/^surrogate:/)
  })

  test('restoring the SAME snapshot twice is idempotent, not duplicating', async () => {
    if (!alive) return
    await restoreGraph(session!, preMigrationCerts(), [], { projectId: PID })
    await restoreGraph(session!, preMigrationCerts(), [], { projectId: PID })
    const res = await session!.run(
      'MATCH (c:Certificate {project_id: $pid}) RETURN count(c) AS n', { pid: PID })
    expect(res.records[0].get('n').toNumber()).toBe(2)
  })

  test('a snapshot that already carries cert_key keeps it untouched', async () => {
    if (!alive) return
    const node: RestorableNode = {
      labels: ['Certificate'], _exportId: 'c3',
      properties: { user_id: UID, cert_key: 'sha256:deadbeef', subject_cn: 'x.acme.test' },
    }
    await restoreGraph(session!, [node], [], { projectId: PID })
    const res = await session!.run(
      'MATCH (c:Certificate {project_id: $pid}) RETURN c.cert_key AS k', { pid: PID })
    expect(res.records[0].get('k')).toBe('sha256:deadbeef')
  })

  test('the restore writes into the target project only', async () => {
    if (!alive) return
    await restoreGraph(session!, preMigrationCerts(), [], { projectId: PID })
    const res = await session!.run(
      'MATCH (c:Certificate {project_id: $other}) RETURN count(c) AS n',
      { other: `${PID}_OTHER` })
    expect(res.records[0].get('n').toNumber()).toBe(0)
  })
})
