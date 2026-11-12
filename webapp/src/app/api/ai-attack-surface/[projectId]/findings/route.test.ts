/**
 * AI Gauntlet findings carry the Vulnerability's graph Node ID.
 *
 * Run: npx vitest run "src/app/api/ai-attack-surface/[projectId]/findings/route.test.ts"
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: string[] = []
let rows: Array<Record<string, unknown>> = []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string) => {
      runCalls.push(cypher)
      return { records: rows.map(row => ({ get: (k: string) => row[k] })) }
    },
    close: async () => {},
  }),
}))

const route = await import('./route')

const call = () =>
  route.GET({} as never, { params: Promise.resolve({ projectId: 'p1' }) })

beforeEach(() => {
  runCalls.length = 0
  rows = []
})

describe('AI findings Node ID', () => {
  test('is projected from the row node, after the one-row-per-finding collapse', async () => {
    await call()
    const q = runCalls[0]
    expect(q).toContain('toString(id(v)) AS nodeId')
    // The id rides on the finding row; it is not part of any grouping key.
    expect(q.indexOf('head(collect(parent))')).toBeLessThan(q.indexOf('toString(id(v))'))
  })

  test('each finding maps it beside its stored id', async () => {
    rows = [{ id: 'aiatk_1', nodeId: '812', source: 'garak' }, { id: 'aiatk_2', source: 'pyrit' }]
    const body = await (await call()).json()
    expect(body.findings.map((f: { id: string; nodeId: unknown }) => [f.id, f.nodeId]))
      .toEqual([['aiatk_1', '812'], ['aiatk_2', null]])
  })
})
