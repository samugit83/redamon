/**
 * R-15: an import must never match, move or delete a node of another project.
 *
 * The agent-session labels (AttackChain, ChainStep, ChainFinding, ChainDecision,
 * ChainFailure) are unique on their id ALONE (graph_db/schema_keys.py). The restore
 * MERGEd them on that id, so importing an export into the instance that still held
 * the source project matched the source's chain nodes and re-stamped them with the
 * import's project_id and user_id; deleting the import then deleted them. Since a
 * co-owner may export a shared project (5.2b), importing it under their own account
 * moved the OWNER's chains into the collaborator's tenant.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/graphRestore.globalIds.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { existsSync, readFileSync } from 'fs'
import path from 'path'
import type { Session } from 'neo4j-driver'
import { restoreGraph, SESSION_ID_KEYS, GLOBAL_REFERENCE_LABELS } from './graphRestore'

interface Call { cypher: string; params: Record<string, unknown> }
type Written = { labels: string[]; properties: Record<string, unknown> }

/** The chain constraints a live database holds (schema_keys.py): id alone, no tenant. */
const LIVE_CONSTRAINTS = [
  { label: 'AttackChain', properties: ['chain_id'] },
  { label: 'ChainStep', properties: ['step_id'] },
  { label: 'ChainFinding', properties: ['finding_id'] },
  { label: 'ChainDecision', properties: ['decision_id'] },
  { label: 'ChainFailure', properties: ['failure_id'] },
  { label: 'Vulnerability', properties: ['id', 'user_id', 'project_id'] },
]

function fakeSession(constraints = LIVE_CONSTRAINTS): { session: Session; calls: Call[] } {
  const calls: Call[] = []
  const run = vi.fn(async (cypher: string, params: Record<string, unknown> = {}) => {
    calls.push({ cypher, params })
    if (cypher.includes('SHOW CONSTRAINTS')) {
      return {
        records: constraints.map(c => ({ get: (k: string) => (k === 'label' ? c.label : c.properties) })),
      }
    }
    return { records: [] }
  })
  return { session: { run } as unknown as Session, calls }
}

const node = (label: string, properties: Record<string, unknown>, id: string) =>
  ({ labels: [label], properties, _exportId: id })

/** An export of project A (owner `ownerA`): one chain, a step, a decision, a finding, a failure. */
function exportOfA() {
  const tenant = { user_id: 'ownerA', project_id: 'PA' }
  return {
    nodes: [
      node('AttackChain', { chain_id: 'sess-A', title: 'chain of A', ...tenant }, 'e-ac'),
      node('ChainStep', { step_id: 'step-1', chain_id: 'sess-A', iteration: 1, ...tenant }, 'e-s1'),
      node('ChainStep', { step_id: 'step-2', chain_id: 'sess-A', iteration: 2, ...tenant }, 'e-s2'),
      node('ChainDecision', { decision_id: 'dec-1', chain_id: 'sess-A', ...tenant }, 'e-d1'),
      node('ChainFinding', { finding_id: 'fnd-1', chain_id: 'sess-A', ...tenant }, 'e-f1'),
      node('ChainFailure', { failure_id: 'fail-1', chain_id: 'sess-A', ...tenant }, 'e-x1'),
      node('Vulnerability', { id: 'vuln-1', ...tenant }, 'e-v1'),
    ],
    relationships: [
      { startExportId: 'e-ac', endExportId: 'e-s1', type: 'HAS_STEP', properties: { order: 1 } },
      { startExportId: 'e-s1', endExportId: 'e-s2', type: 'NEXT_STEP', properties: {} },
      { startExportId: 'e-s1', endExportId: 'e-d1', type: 'LED_TO', properties: {} },
      { startExportId: 'e-s2', endExportId: 'e-f1', type: 'PRODUCED', properties: {} },
      { startExportId: 'e-s2', endExportId: 'e-x1', type: 'FAILED_WITH', properties: {} },
    ],
  }
}

const SOURCE_IDS = ['sess-A', 'step-1', 'step-2', 'dec-1', 'fnd-1', 'fail-1']

function written(calls: Call[]): Written[] {
  return calls
    .filter(c => c.cypher.includes('apoc.merge.node') || c.cypher.includes('apoc.create.node'))
    .flatMap(c => c.params.nodes as Written[])
}

const byLabel = (nodes: Written[], label: string) => nodes.filter(n => n.labels.includes(label))

describe('restoreGraph — agent-session ids (R-15)', () => {
  for (const [what, userId] of [['the same user', 'ownerA'], ['another owner', 'collab']] as const) {
    test(`an import by ${what} writes no node under a source id, so it can match none of A's`, async () => {
      const { session, calls } = fakeSession()
      const { nodes, relationships } = exportOfA()
      await restoreGraph(session, nodes, relationships, { projectId: 'PB', userId })

      const out = written(calls)
      expect(out).toHaveLength(nodes.length)
      for (const n of out) {
        for (const [label, key] of Object.entries(SESSION_ID_KEYS)) {
          if (n.labels.includes(label)) expect(SOURCE_IDS).not.toContain(n.properties[key])
        }
        if ('chain_id' in n.properties) expect(SOURCE_IDS).not.toContain(n.properties.chain_id)
        expect(n.properties).toMatchObject({ user_id: userId, project_id: 'PB' })
      }
    })
  }

  test('every session node of the import names the import\'s own chain', async () => {
    const { session, calls } = fakeSession()
    const { nodes, relationships } = exportOfA()
    await restoreGraph(session, nodes, relationships, { projectId: 'PB', userId: 'collab' })

    const out = written(calls)
    const [chain] = byLabel(out, 'AttackChain')
    const newChainId = chain.properties.chain_id as string
    expect(newChainId).toBeTruthy()
    for (const label of ['ChainStep', 'ChainDecision', 'ChainFinding', 'ChainFailure']) {
      for (const n of byLabel(out, label)) expect(n.properties.chain_id).toBe(newChainId)
    }
    // Two steps keep two distinct identities.
    const stepIds = byLabel(out, 'ChainStep').map(n => n.properties.step_id)
    expect(new Set(stepIds).size).toBe(2)
  })

  test("the chain takes the id the caller renamed it to (the import's conversation session)", async () => {
    const { session, calls } = fakeSession()
    const { nodes, relationships } = exportOfA()
    await restoreGraph(session, nodes, relationships, {
      projectId: 'PB', userId: 'ownerA', renamedChainIds: new Map([['sess-A', 'sess-A_imported_1234abcd']]),
    })
    const out = written(calls)
    expect(byLabel(out, 'AttackChain')[0].properties.chain_id).toBe('sess-A_imported_1234abcd')
    for (const n of byLabel(out, 'ChainStep')) expect(n.properties.chain_id).toBe('sess-A_imported_1234abcd')
  })

  test('a session node is merged inside the target project, never on its id alone', async () => {
    const { session, calls } = fakeSession()
    const { nodes, relationships } = exportOfA()
    await restoreGraph(session, nodes, relationships, { projectId: 'PB', userId: 'collab' })
    const merges = calls.filter(c => c.cypher.includes('apoc.merge.node'))
    const chainMerge = merges.find(c => (c.params.nodes as Written[])[0].labels.includes('AttackChain'))!
    expect(chainMerge.cypher).toContain('`chain_id`: node.properties.`chain_id`')
    expect(chainMerge.cypher).toContain('`project_id`: node.properties.`project_id`')
    expect(chainMerge.cypher).toContain('`user_id`: node.properties.`user_id`')
  })

  test('edges are still wired by export id inside the target project', async () => {
    const { session, calls } = fakeSession()
    const { nodes, relationships } = exportOfA()
    await restoreGraph(session, nodes, relationships, { projectId: 'PB', userId: 'collab' })
    const rel = calls.find(c => c.cypher.includes('apoc.create.relationship'))!
    expect(rel.params.pid).toBe('PB')
    expect(rel.params.rels).toEqual(relationships)
  })

  test("a tenant-keyed finding keeps its id: only the global ids are replaced", async () => {
    const { session, calls } = fakeSession()
    const { nodes, relationships } = exportOfA()
    await restoreGraph(session, nodes, relationships, { projectId: 'PB', userId: 'collab' })
    expect(byLabel(written(calls), 'Vulnerability')[0].properties.id).toBe('vuln-1')
  })

  test('the payload is not mutated (a snapshot may be restored again)', async () => {
    const { session } = fakeSession()
    const { nodes, relationships } = exportOfA()
    const before = JSON.stringify(nodes)
    await restoreGraph(session, nodes, relationships, { projectId: 'PB', userId: 'collab' })
    expect(JSON.stringify(nodes)).toBe(before)
  })

  test('a session label with no constraint in this database still gets fresh ids', async () => {
    // CREATEd rather than MERGEd, it could not move A's node; but a chain id held by two
    // projects makes the agent refuse every later write to A's chain (_chain_held_elsewhere).
    const { session, calls } = fakeSession([])
    const { nodes, relationships } = exportOfA()
    await restoreGraph(session, nodes, relationships, { projectId: 'PB', userId: 'collab' })
    expect(byLabel(written(calls), 'AttackChain')[0].properties.chain_id).not.toBe('sess-A')
  })
})

describe('restoreGraph — every label merged on a global id is handled', () => {
  const SCHEMA_KEYS = path.resolve(__dirname, '../../../graph_db/schema_keys.py')

  /** label -> key properties, read from the single declaration of the graph's keys. */
  function schemaKeys(): Map<string, string[]> {
    const src = readFileSync(SCHEMA_KEYS, 'utf8')
    const out = new Map<string, string[]>()
    for (const m of src.matchAll(/"label":\s*"(\w+)"[\s\S]*?"key_properties":\s*\[([^\]]*)\]/g)) {
      out.set(m[1], [...m[2].matchAll(/"(\w+)"/g)].map(k => k[1]))
    }
    return out
  }

  // A new label keyed without the tenant must be decided here: a project label is
  // remapped like the session ones, a global one never reaches an export.
  const NEVER_IN_A_PROJECT_GRAPH = ['KBChunk']

  test.skipIf(!existsSync(SCHEMA_KEYS))('a global key is a reference, session or knowledge-base label', () => {
    const keys = schemaKeys()
    expect(keys.size).toBeGreaterThan(40)
    const global = [...keys].filter(([, k]) => !(k.includes('user_id') && k.includes('project_id')))
    for (const [label] of global) {
      expect([...GLOBAL_REFERENCE_LABELS, ...Object.keys(SESSION_ID_KEYS), ...NEVER_IN_A_PROJECT_GRAPH],
        `${label} is unique on a global id: decide how a restore writes it`).toContain(label)
    }
  })

  test.skipIf(!existsSync(SCHEMA_KEYS))('SESSION_ID_KEYS names the key each session label is unique on', () => {
    const keys = schemaKeys()
    for (const [label, key] of Object.entries(SESSION_ID_KEYS)) expect(keys.get(label)).toEqual([key])
  })

  test('any other label keyed on a global id is merged inside the target project', async () => {
    // Not one today: a constraint on `id` alone (an old database, a future label) would
    // otherwise MERGE onto another project's node. With the tenant in the identity the
    // restore creates its own node, or the constraint refuses it: it never moves one.
    const { session, calls } = fakeSession([{ label: 'Subdomain', properties: ['name'] }])
    await restoreGraph(session, [node('Subdomain', { name: 'a.example.test' }, 'n1')], [], { projectId: 'p1' })
    const merge = calls.find(c => c.cypher.includes('apoc.merge.node'))!
    expect(merge.cypher).toContain('`name`: node.properties.`name`')
    expect(merge.cypher).toContain('`project_id`: node.properties.`project_id`')
    // Activation keeps each node's own user_id, which an old node may lack: not in the identity.
    expect(merge.cypher).not.toContain('`user_id`')
    expect((merge.params.nodes as Written[])[0].properties.name).toBe('a.example.test')
  })
})
