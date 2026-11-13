/** @vitest-environment node */
/**
 * A read-only session against a real Neo4j (fix of the 4.3 review finding 1): Neo4j itself refuses
 * every write in it, so a saved view's Cypher cannot change the graph whatever its text gets past.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network redamon_default -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/app/api/graph/neo4j.readOnly.integration.test.ts'
 * (NEO4J_PASSWORD exported from .env in the same command, never echoed; the network is the one the
 * neo4j container is on: `docker inspect redamon-neo4j`).
 *
 * One throwaway node with a random tag, deleted after the file.
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { type Driver } from 'neo4j-driver'
import { closeDriver, getGraphSession } from './neo4j'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''
const TAG = `rbac-readonly-${Math.random().toString(36).slice(2, 10)}`

let admin: Driver | undefined
let alive = false

async function probes(): Promise<number> {
  const s = admin!.session()
  try {
    const r = await s.run('MATCH (n:RbacReadOnlyProbe {tag: $tag}) RETURN count(n) AS c', { tag: TAG })
    return r.records[0].get('c').toNumber()
  } finally {
    await s.close()
  }
}

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    admin = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    const s = admin.session()
    await s.run('CREATE (:RbacReadOnlyProbe {tag: $tag, name: $tag})', { tag: TAG })
    await s.close()
    alive = true
  } catch { alive = false }
})

afterAll(async () => {
  if (admin) {
    if (alive) {
      const s = admin.session()
      await s.run('MATCH (n:RbacReadOnlyProbe {tag: $tag}) DETACH DELETE n', { tag: TAG })
      await s.close()
    }
    await admin.close()
  }
  await closeDriver()
})

describe.skipIf(!PASSWORD)('getGraphSession({readOnly: true}) on a real Neo4j', () => {
  test.for([
    ['DETACH DELETE', 'MATCH (n:RbacReadOnlyProbe {tag: $tag}) DETACH DELETE n'],
    ['SET', "MATCH (n:RbacReadOnlyProbe {tag: $tag}) SET n.name = 'changed'"],
    ['CREATE', 'CREATE (:RbacReadOnlyProbe {tag: $tag, name: "second"})'],
  ] as const)('%s is refused by Neo4j (AccessMode) and changes nothing', async ([, query], ctx) => {
    if (!alive) ctx.skip()
    const session = getGraphSession({ readOnly: true })
    try {
      await expect(session.run(query, { tag: TAG })).rejects.toMatchObject({ code: 'Neo.ClientError.Statement.AccessMode' })
    } finally {
      await session.close()
    }
    expect(await probes()).toBe(1)
    const s = admin!.session()
    try {
      const r = await s.run('MATCH (n:RbacReadOnlyProbe {tag: $tag}) RETURN n.name AS name', { tag: TAG })
      expect(r.records[0].get('name')).toBe(TAG)
    } finally {
      await s.close()
    }
  })

  test('a read runs as before', async (ctx) => {
    if (!alive) ctx.skip()
    const session = getGraphSession({ readOnly: true })
    try {
      const r = await session.run('MATCH (n:RbacReadOnlyProbe {tag: $tag}) RETURN n.name AS name', { tag: TAG })
      expect(r.records.map(rec => rec.get('name'))).toEqual([TAG])
    } finally {
      await session.close()
    }
  })
})
