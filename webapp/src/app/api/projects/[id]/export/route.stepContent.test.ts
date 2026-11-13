/**
 * The export bundles the whole project: nodes.json, but also every conversation's chat messages
 * and the raw scan artifacts (recon_*.json, gvm_*.json, github_hunt_*.json). So it needs Raw data
 * & files (R*) on top of `project:export` (4.9 review): a reader below R* (Phase 5's Manage
 * collaborator without Raw data, should one exist) gets 403 before anything is read. The owner and
 * a reader with Raw data & files get the bundle with every chain node whole; `neo4j/nodes.json`
 * still passes through the step-content helper, as every graph output does.
 *
 * Runs the real export route; the guard answers a context with the access under test, Prisma
 * answers every query with nothing, the graph export is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ access: null as unknown, reads: [] as string[] }))

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
      h.reads.push(`${name}.${method}`)
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
  exportProjectGraph: async () => (h.reads.push('graph'), {
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
  h.reads.length = 0
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('the export: Raw data & files first, then neo4j/nodes.json whole', () => {
  test.each([
    ['the owner', access('owner', true, 'owner')],
    ['a reader with Raw data & files', access('read', true, 'share')],
  ])('%s: every chain node whole', async (_who, a) => {
    h.access = a
    expect(await exportedNodes()).toEqual(NODES)
  })

  test.each([
    ['a read share without Raw data', access('read', false, 'share')],
    ['an overseer', access('read', false, 'oversight')],
  ])('%s: 403 naming project:export and R*, before any read (the zip carries chat messages and raw artifacts)', async (_who, a) => {
    h.access = a
    const res = await GET(new Request('http://localhost:3000/api/projects/p1/export') as never, { params: Promise.resolve({ id: 'p1' }) })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:export', level: 'R*' })
    expect(h.reads).toEqual([])
  })
})
