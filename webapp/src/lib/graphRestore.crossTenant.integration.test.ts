/** @vitest-environment node */
/**
 * R-15 against a real Neo4j: importing an export of project A into the same database
 * leaves A's attack chain where it is (count, ids, owner), and deleting the import
 * does not take it. Before the fix the restore MERGEd the chain nodes on their id
 * alone, re-stamped A's nodes into the import, and the import's delete removed them.
 *
 * The export is read by the real export code (projectExport/graph.ts) and restored by
 * the real restore, as POST /api/projects/import does.
 *
 * Skipped unless a Neo4j answers. It writes only projects with random ids and removes
 * them; run it against a throwaway database, e.g.:
 *   docker run -d --name r15-neo4j -p 127.0.0.1:17687:7687 -e NEO4J_AUTH=neo4j/<pw> \
 *     -e NEO4J_PLUGINS='["apoc"]' neo4j:5.26-community
 *   NEO4J_URI=bolt://localhost:17687 NEO4J_PASSWORD=<pw> \
 *     npx vitest run --no-file-parallelism src/lib/graphRestore.crossTenant.integration.test.ts
 */
import { describe, test, expect, beforeAll, afterAll, afterEach } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { clearProjectGraph, restoreGraph } from './graphRestore'
import { exportProjectGraph } from './projectExport/graph'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

const rnd = () => Math.random().toString(36).slice(2, 10)
const PA = `R15_PA_${rnd()}`
const PB = `R15_PB_${rnd()}`
const OWNER = `r15-owner-${rnd()}`
const COLLAB = `r15-collab-${rnd()}`
const SESSION_ID = `r15-session-${rnd()}`

let driver: Driver | undefined
let session: Session | undefined
let alive = false

/** The chain constraints graph_db/schema.py creates (schema_keys.py): id alone, same names. */
const CHAIN_CONSTRAINTS = [
  ['attack_chain_id', 'AttackChain', 'chain_id'],
  ['chain_step_id', 'ChainStep', 'step_id'],
  ['chain_finding_id', 'ChainFinding', 'finding_id'],
  ['chain_decision_id', 'ChainDecision', 'decision_id'],
  ['chain_failure_id', 'ChainFailure', 'failure_id'],
]

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    session = driver.session()
    await session.run('RETURN 1')
    for (const [name, label, key] of CHAIN_CONSTRAINTS) {
      await session.run(`CREATE CONSTRAINT ${name} IF NOT EXISTS FOR (n:${label}) REQUIRE n.${key} IS UNIQUE`)
    }
    alive = true
  } catch { alive = false }
})

afterEach(async () => {
  if (alive && session) {
    await session.run('MATCH (n) WHERE n.project_id IN $pids DETACH DELETE n', { pids: [PA, PB] })
  }
})

afterAll(async () => {
  if (session) await session.close()
  if (driver) await driver.close()
})

/** Project A's chain as the agent writes it: a chain, two steps, a decision, a finding. */
async function seedChainOfA(): Promise<void> {
  await session!.run(
    `CREATE (ac:AttackChain {chain_id: $sid, user_id: $uid, project_id: $pid, title: 'chain of A'})
     CREATE (s1:ChainStep {step_id: $sid + '-s1', chain_id: $sid, user_id: $uid, project_id: $pid, iteration: 1})
     CREATE (s2:ChainStep {step_id: $sid + '-s2', chain_id: $sid, user_id: $uid, project_id: $pid, iteration: 2})
     CREATE (d:ChainDecision {decision_id: $sid + '-d1', chain_id: $sid, user_id: $uid, project_id: $pid})
     CREATE (f:ChainFinding {finding_id: $sid + '-f1', chain_id: $sid, user_id: $uid, project_id: $pid})
     CREATE (sub:Subdomain {name: 'www.example.test', user_id: $uid, project_id: $pid})
     CREATE (ac)-[:HAS_STEP {order: 1}]->(s1)-[:NEXT_STEP]->(s2)
     CREATE (s1)-[:LED_TO]->(d)
     CREATE (s2)-[:PRODUCED]->(f)
     CREATE (s1)-[:STEP_TARGETED]->(sub)`,
    { sid: SESSION_ID, uid: OWNER, pid: PA })
}

interface ChainRow { label: string; id: string; uid: string; chain: string }

/** Every session node of a project, with its own id, owner and chain id. */
async function chainNodes(pid: string): Promise<ChainRow[]> {
  const res = await session!.run(
    `MATCH (n {project_id: $pid})
     WHERE n:AttackChain OR n:ChainStep OR n:ChainDecision OR n:ChainFinding OR n:ChainFailure
     RETURN labels(n)[0] AS label,
            coalesce(n.step_id, n.decision_id, n.finding_id, n.failure_id, n.chain_id) AS id,
            n.user_id AS uid, n.chain_id AS chain
     ORDER BY label, id`,
    { pid })
  return res.records.map(r => ({ label: r.get('label'), id: r.get('id'), uid: r.get('uid'), chain: r.get('chain') }))
}

async function importAInto(pid: string, userId: string, renamedChainIds?: Map<string, string>): Promise<void> {
  const exported = await exportProjectGraph(session!, PA)
  await clearProjectGraph(session!, pid)
  await restoreGraph(session!, exported.nodes, exported.relationships, {
    projectId: pid, userId, ...(renamedChainIds ? { renamedChainIds } : {}),
  })
}

describe.skipIf(!PASSWORD)('import of project A into the same database (R-15)', () => {
  for (const [who, importer] of [['the same user', () => OWNER], ["another owner (a co-owner's export)", () => COLLAB]] as const) {
    test(`by ${who}: A's chain keeps its nodes, ids and owner, and survives the import's delete`, async () => {
      if (!alive) return
      await seedChainOfA()
      const before = await chainNodes(PA)
      expect(before).toHaveLength(5)

      await importAInto(PB, importer())

      expect(await chainNodes(PA)).toEqual(before)
      const imported = await chainNodes(PB)
      expect(imported).toHaveLength(5)
      const sourceIds = new Set(before.map(r => r.id))
      for (const row of imported) {
        expect(sourceIds.has(row.id)).toBe(false)
        expect(row.uid).toBe(importer())
      }
      const importedChain = imported.find(r => r.label === 'AttackChain')!.id
      for (const row of imported) expect(row.chain).toBe(importedChain)

      // The import's own edges are rebuilt between its own nodes.
      const wired = await session!.run(
        `MATCH (ac:AttackChain {project_id: $pid})-[:HAS_STEP]->(s1:ChainStep {project_id: $pid})
               -[:NEXT_STEP]->(s2:ChainStep {project_id: $pid})-[:PRODUCED]->(f:ChainFinding {project_id: $pid})
         MATCH (s1)-[:LED_TO]->(d:ChainDecision {project_id: $pid})
         RETURN count(*) AS n`, { pid: PB })
      expect(wired.records[0].get('n').toNumber()).toBe(1)

      await clearProjectGraph(session!, PB)
      expect(await chainNodes(PB)).toHaveLength(0)
      expect(await chainNodes(PA)).toEqual(before)
    })
  }

  test("the import's chain takes its conversation's renamed session id", async () => {
    if (!alive) return
    await seedChainOfA()
    const renamed = `${SESSION_ID}_imported_${rnd()}`
    await importAInto(PB, COLLAB, new Map([[SESSION_ID, renamed]]))
    const imported = await chainNodes(PB)
    expect(imported.find(r => r.label === 'AttackChain')!.id).toBe(renamed)
    for (const row of imported) expect(row.chain).toBe(renamed)
    expect((await chainNodes(PA)).every(r => r.uid === OWNER && r.chain === SESSION_ID)).toBe(true)
  })
})
