/**
 * The export's `neo4j/nodes.json` passes through the step-content helper (step 4.9, SH-30), as every
 * output that serialises chain nodes does. `project:export` is Manage, so in Phase 4 only the owner
 * (whole: it reaches `R*`) gets an export; a reader below `R*` stands for Phase 5's Manage
 * collaborator without Raw data & files, who would get each chain node without its content. The
 * other node labels, and the relationships, are untouched.
 *
 * Runs the real export route; the guard answers a context with the access under test, Prisma
 * answers every query with nothing, the graph export is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ access: null as unknown }))

const PROJECT = {
  id: 'p1', userId: 'alice', name: 'Example project', targetDomain: 'rbac.test', engagementKind: 'internal',
  createdAt: new Date('2026-01-01T00:00:00Z'), updatedAt: new Date('2026-01-01T00:00:00Z'),
}
const CONTENT = {
  thought: 'rbac-fake-thought', reasoning: 'rbac-fake-reasoning', output_summary: 'rbac-fake-summary',
  output_analysis: 'rbac-fake-analysis', tool_args_summary: 'curl -u admin:rbac-fake-pass http://app.rbac.test', error_message: 'rbac-fake-error',
}
const NODES = [
  { labels: ['ChainStep'], properties: { step_id: 's-1', chain_id: 'c-1', tool_name: 'curl', iteration: 1, ...CONTENT }, _exportId: 'e1' },
  { labels: ['ChainFailure'], properties: { failure_id: 'f-1', failure_type: 'tool_error', error_message: 'rbac-fake-error', lesson_learned: 'rbac-fake-analysis' }, _exportId: 'e2' },
  { labels: ['ChainDecision'], properties: { decision_id: 'd-1', decision_type: 'phase_transition', reason: 'rbac-fake-reason' }, _exportId: 'e3' },
  { labels: ['Domain'], properties: { name: 'app.rbac.test', user_id: 'alice', project_id: 'p1' }, _exportId: 'e4' },
]

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_r: unknown, permission: string) => ({ permission, effective: { userId: 'alice' }, access: h.access }),
}))
vi.mock('@/lib/prisma', () => {
  const model = (name: string) => new Proxy({}, {
    get: (_t, method: string) => async () => {
      if (name === 'project' && (method === 'findUnique' || method === 'findFirst')) return PROJECT
      if (method === 'findMany') return []
      if (method === 'count') return 0
      return null
    },
  })
  return { default: new Proxy({}, { get: (_t, name: string) => model(name) }) }
})
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: async () => ({ records: [] }), close: async () => {} }) }))
vi.mock('@/lib/projectExport/graph', () => ({
  exportProjectGraph: async () => ({
    nodes: NODES.map(n => ({ ...n, properties: { ...n.properties } })),
    relationships: [{ type: 'FAILED_WITH', startExportId: 'e1', endExportId: 'e2', properties: {} }],
    referenceLinks: [],
  }),
}))
vi.mock('@/lib/reconPresets/server', () => ({ projectPresetForRead: () => ({ settings: {} }) }))
vi.mock('fs', async (orig) => ({ ...(await orig<typeof import('fs')>()), existsSync: () => false, readdirSync: () => [] }))

import { GET } from './route'
import { STEP_CONTENT_PROPS } from '@/lib/authz/stepContent'

const access = (level: string, rawData: boolean, via: string) => ({ project: { id: 'p1', userId: 'alice' }, level, toggles: { rawData }, via })

async function exportedNodes(): Promise<Array<{ labels: string[]; properties: Record<string, unknown>; _exportId: string }>> {
  const res = await GET(new Request('http://localhost:3000/api/projects/p1/export') as never, { params: Promise.resolve({ id: 'p1' }) })
  expect(res.status).toBe(200)
  const zip = await JSZip.loadAsync(await res.arrayBuffer())
  const manifest = JSON.parse(await zip.file('manifest.json')!.async('string'))
  expect(manifest.stats.neo4jNodes).toBe(NODES.length)
  return JSON.parse(await zip.file('neo4j/nodes.json')!.async('string'))
}

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('the export\'s neo4j/nodes.json', () => {
  test.each([
    ['the owner', access('owner', true, 'owner')],
    ['a reader with Raw data & files', access('read', true, 'share')],
  ])('%s: every chain node whole', async (_who, a) => {
    h.access = a
    expect(await exportedNodes()).toEqual(NODES)
  })

  test('a reader below R* (Phase 5\'s Manage without Raw data): the chain nodes without their content, the rest whole', async () => {
    h.access = access('read', false, 'share')
    const nodes = await exportedNodes()
    expect(nodes.map(n => n._exportId)).toEqual(['e1', 'e2', 'e3', 'e4'])
    for (const key of STEP_CONTENT_PROPS) expect(nodes[0].properties).not.toHaveProperty(key)
    expect(nodes[0].properties).toEqual({ step_id: 's-1', chain_id: 'c-1', tool_name: 'curl', iteration: 1 })
    expect(nodes[1].properties).toEqual({ failure_id: 'f-1', failure_type: 'tool_error' })
    expect(nodes[2].properties).toEqual({ decision_id: 'd-1', decision_type: 'phase_transition' })
    expect(nodes[3]).toEqual(NODES[3])
    expect(JSON.stringify(nodes)).not.toMatch(/rbac-fake/)
  })
})
