/**
 * The preview's judgement of the names found last run (lib/ipHostnamePreview):
 * the inputs the rule needs from the graph (IP attribution for scan_all), the
 * guardrail and RoE predicates, and the one-row-per-name read.
 *
 * Run: npx vitest run src/lib/ipHostnamePreview.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  type PreviewGraph, type PreviewProjectRow, buildIpHostnamePreview, readPreviewGraph,
} from './ipHostnamePreview'

const ROW: PreviewProjectRow = {
  id: 'p1', userId: 'u1', ipMode: true, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true,
  ipHostnameInclude: [], ipHostnameExclude: [], ipHostnameMaxScanned: 100, roeExcludedHosts: [],
}

const name = (n: string, ips = ['203.0.113.10'], over: Partial<PreviewGraph['names'][number]> = {}) => ({
  name: n, ips, sources: ['tlsx_san'], reason: 'record_only', last_seen: null, kind: 'recorded' as const,
  org: n.split('.').slice(-2).join('.'), evaluatedAt: null, ...over,
})

const graph = (over: Partial<PreviewGraph> = {}): PreviewGraph => ({
  names: [], sharedEdge: [], attributionFailed: [], attributed: 2, ipCount: 2, lastRunMode: null,
  legacyNames: 0, seenEdges: 1, ...over,
})

const results = (g: PreviewGraph, row: PreviewProjectRow = ROW) =>
  Object.fromEntries(buildIpHostnamePreview(g, row).recorded.map(r => [r.name, r.result]))

describe('scan_all reads IP attribution from the graph', () => {
  test('a name on a shared edge is refused; one on a dedicated IP is not', () => {
    const g = graph({
      names: [name('app.example.com'), name('cdn.example.org', ['203.0.113.20'])],
      sharedEdge: ['203.0.113.20'],
    })
    expect(results(g)).toEqual({ 'app.example.com': 'scanned', 'cdn.example.org': 'shared_edge_ip' })
  })

  test('attribution that never ran refuses every name (unknown is not "no edge")', () => {
    expect(results(graph({ names: [name('app.example.com')], attributed: 0 })))
      .toEqual({ 'app.example.com': 'attribution_unavailable' })
  })

  test('an IP whose attribution failed refuses the names seen on it', () => {
    expect(results(graph({ names: [name('app.example.com')], attributionFailed: ['203.0.113.10'] })))
      .toEqual({ 'app.example.com': 'attribution_unavailable' })
  })
})

describe('the guardrail and the RoE apply to every name', () => {
  test('a protected domain is hard_blocked, an RoE-excluded name roe_excluded', () => {
    const g = graph({ names: [name('portal.example.gov'), name('old.example.com'), name('app.example.com')] })
    expect(results(g, { ...ROW, roeExcludedHosts: ['old.example.com'] })).toEqual({
      'portal.example.gov': 'hard_blocked',
      'old.example.com': 'roe_excluded',
      'app.example.com': 'scanned',
    })
  })

  test('a name with no registrable domain is refused in a scanning mode', () => {
    expect(results(graph({ names: [name('app.example.com', undefined, { org: null })] })))
      .toEqual({ 'app.example.com': 'no_registrable_domain' })
  })
})

describe('legacy: a graph from before hostname recording', () => {
  test('real names under the mock root, no SEEN_ON, no run-mode stamp: legacy', () => {
    expect(buildIpHostnamePreview(graph({ legacyNames: 3, seenEdges: 0, lastRunMode: null }), ROW).legacy).toBe(true)
  })

  test('the run-mode stamp says a run since then wrote the graph: never legacy', () => {
    for (const lastRunMode of ['ip_only', 'record_only', 'record_filter', 'scan_all']) {
      expect(buildIpHostnamePreview(graph({ legacyNames: 3, seenEdges: 0, lastRunMode }), ROW).legacy, lastRunMode)
        .toBe(false)
    }
  })
})

describe('the graph read', () => {
  // run() only, as getGraphSession wraps it with the query timeout; a read
  // through executeRead would fail here.
  const fakeSession = (names: Record<string, unknown>[], ctx: Record<string, unknown>) => ({
    run: async (q: string) => ({
      records: (q.includes('UNION ALL') ? names : [ctx]).map(r => ({ get: (k: string) => r[k] })),
    }),
  }) as never

  test('a name both recorded and selected is one row, as the selection left it', async () => {
    const g = await readPreviewGraph(fakeSession([
      { name: 'app.example.com', kind: 'scanned', reason: 'scanned', ips: ['203.0.113.10'], sources: ['ptr'] },
      { name: 'app.example.com', kind: 'recorded', reason: 'record_only', ips: ['203.0.113.10'], sources: ['tlsx_san'] },
    ], { ipCount: { toNumber: () => 1 }, attributed: 1, legacyNames: 0, seenEdges: 1 }), 'u1', 'p1')
    expect(g.names).toHaveLength(1)
    expect(g.names[0]).toMatchObject({ kind: 'scanned', reason: 'scanned', sources: ['ptr'] })
    expect(g.ipCount).toBe(1)
  })

  test('IPv6 addresses come back in one spelling, so per-IP totals do not split', async () => {
    const g = await readPreviewGraph(fakeSession([
      { name: 'v6.example.com', kind: 'recorded', reason: 'record_only', ips: ['2001:DB8:0:0::1'], sources: [] },
    ], {}), 'u1', 'p1')
    expect(g.names[0].ips).toEqual(['2001:db8::1'])
  })
})
