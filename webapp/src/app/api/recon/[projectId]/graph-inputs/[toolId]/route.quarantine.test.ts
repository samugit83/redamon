/** @vitest-environment node */
/**
 * The partial window's counts never promise a target the tool then skips: every
 * tool that requests graph Endpoints excludes the quarantined ones, with the
 * same predicate the Python graph builders use (graph_builders.QUARANTINED).
 *
 * Run: npx vitest run "src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.quarantine.test.ts"
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { notQuarantined } from '@/lib/graph/requestTargets'

const mockRun = vi.fn()

vi.mock('@/lib/access', () => ({ guardProject: () => Promise.resolve(null) }))
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: () => Promise.resolve({ userId: 'u1', targetDomain: 'acme.test' }) } },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: vi.fn() }),
}))

import { GET } from './route'

const ENDPOINT_TOOLS = ['Nuclei', 'RouteExposure', 'Arjun', 'ZapAjaxSpider', 'JsRecon', 'GraphqlScan',
  'SerializedScan', 'SupplyChainRecon', 'WebCachePoison']

beforeEach(() => {
  vi.clearAllMocks()
  mockRun.mockResolvedValue({ records: [{ get: () => null }] })
})

async function cypherFor(toolId: string): Promise<string> {
  await GET({} as never, { params: Promise.resolve({ projectId: 'p1', toolId }) })
  return mockRun.mock.calls.map(c => String(c[0])).join('\n')
}

describe('quarantined endpoints are not counted', () => {
  test.each(ENDPOINT_TOOLS)('%s counts only requestable Endpoints', async (toolId) => {
    const cypher = await cypherFor(toolId)
    expect(cypher).toContain('(e:Endpoint')
    expect(cypher).toContain(notQuarantined('e'))
  })

  test('the fragment is the Python builders\' predicate', () => {
    const builders = readFileSync(
      resolve(__dirname, '../../../../../../../../recon/partial_recon_modules/graph_builders.py'), 'utf8')
    expect(builders).toContain('QUARANTINED = "coalesce({a}.quarantined, false)"')
    expect(notQuarantined('e')).toBe('NOT coalesce(e.quarantined, false)')
  })
})
