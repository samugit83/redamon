/**
 * GET /api/projects/[id]/versions/[versionId]/graph on a shared project (step 4.7, SH-30): the
 * current version is the live graph, so a reader without Raw data & files gets each ChainStep's
 * structure without its content (thought, reasoning, outputs, command line, error); the owner and a
 * share with Raw data get it whole, and the graph the live read returned (the shared cache) is never
 * changed. A past version's snapshot holds no chain nodes, but passes through the same helper.
 *
 * The guard answers a context with the access under test; the version lookup, the live read and the
 * snapshot are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  access: null as unknown,
  versionRow: vi.fn(),
  live: { nodes: [] as unknown[], links: [] as unknown[] },
  snapshot: { nodes: [] as unknown[], relationships: [] as unknown[] },
}))

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_r: unknown, permission: string) => ({ permission, effective: { userId: 'carol' }, access: h.access }),
}))
vi.mock('@/lib/prisma', () => ({ default: { $queryRaw: (...a: unknown[]) => h.versionRow(...a) } }))
vi.mock('@/lib/scanSnapshot', async (orig) => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  loadSnapshot: async () => h.snapshot,
}))
vi.mock('@/app/api/graph/liveRead', () => ({ readLiveGraph: async () => h.live }))

import { GET } from './route'

const access = (level: string, rawData: boolean) => ({ project: { id: 'p1', userId: 'alice' }, level, toggles: { rawData }, via: level === 'owner' ? 'owner' : 'share' })
const versionRow = (isCurrent: boolean) => [{
  id: 'v1', project_id: 'p1', seq: 1, label: 'Scan 1', is_current: isCurrent, pinned: false,
  node_count: 2, link_count: 1, created_at: new Date('2026-11-01T00:00:00Z'), snapshot_bytes: isCurrent ? 0 : 128,
}]
const CONTENT = {
  thought: 'try the admin panel', reasoning: 'default creds are common', output_summary: '200 OK',
  output_analysis: 'logged in', tool_args_summary: 'curl -u admin:rbac-fake-pass http://target', error_message: 'none',
}
const step = () => ({
  id: '1', name: 'Step 1\ncurl', type: 'ChainStep',
  properties: { step_id: 's1', chain_id: 'c1', iteration: 1, tool_name: 'curl', success: true, ...CONTENT },
})
const host = () => ({ id: '2', name: 'target', type: 'Domain', properties: { name: 'target.rbac.test' } })
const read = async () => (await GET(new NextRequest('http://x/api/projects/p1/versions/v1/graph'), { params: Promise.resolve({ id: 'p1', versionId: 'v1' }) })).json()

beforeEach(() => {
  h.versionRow.mockReset()
  h.versionRow.mockResolvedValue(versionRow(true))
  h.live = { nodes: [step(), host()], links: [{ source: '1', target: '2', type: 'TARGETED' }] }
})

describe('the current version (the live graph)', () => {
  test('a read share without Raw data: the step keeps its structure, loses its content; other nodes untouched', async () => {
    h.access = access('read', false)
    const body = await read()
    expect(body.live).toBe(true)
    const s = body.nodes.find((n: { type: string }) => n.type === 'ChainStep')
    for (const key of Object.keys(CONTENT)) expect(s.properties).not.toHaveProperty(key)
    expect(s.properties).toEqual({ step_id: 's1', chain_id: 'c1', iteration: 1, tool_name: 'curl', success: true })
    expect(body.nodes.find((n: { type: string }) => n.type === 'Domain')).toEqual(host())
    expect(body.links).toHaveLength(1)
    expect(JSON.stringify(body)).not.toContain('rbac-fake-pass')
    // The live read's result (the shared cache) is never changed.
    expect((h.live.nodes[0] as ReturnType<typeof step>).properties).toMatchObject(CONTENT)
  })

  test.each([
    ['the owner', access('owner', true)],
    ['a read share with Raw data & files', access('read', true)],
  ])('%s: the step content is there', async (_who, a) => {
    h.access = a
    const s = (await read()).nodes.find((n: { type: string }) => n.type === 'ChainStep')
    expect(s.properties).toMatchObject(CONTENT)
  })
})

describe('a past version (a snapshot)', () => {
  test('passes through the same helper: a step a snapshot held would lose its content below R*', async () => {
    h.versionRow.mockResolvedValue(versionRow(false))
    h.snapshot = {
      nodes: [{ _exportId: 'e1', labels: ['ChainStep'], properties: { step_id: 's1', ...CONTENT } }],
      relationships: [],
    }
    h.access = access('read', false)
    const body = await read()
    expect(body.live).toBe(false)
    expect(body.nodes[0].properties).toEqual({ step_id: 's1' })
    h.access = access('owner', true)
    expect((await read()).nodes[0].properties).toMatchObject(CONTENT)
  })
})
