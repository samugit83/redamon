/** @vitest-environment node */
/**
 * Secrets seen in a URL a public urlscan scan recorded: they hang off their
 * host (Subdomain, or the org's Domain), carry the value and the full link for
 * display beside a masked URL and the value's length, and are labelled
 * "urlscan history" on the Secrets screen. A node written before the value was
 * kept still shows as masked.
 *
 * Run: npx vitest run src/lib/secrets/urlscanSecret.test.ts
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test, expect, vi } from 'vitest'
import { secretSourceLabel } from './jsReconSecret'

const mockRun = vi.fn()
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: () => Promise.resolve(null) }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: vi.fn() }),
}))

describe('urlscan secrets', () => {
  test('the source reads as urlscan history', () => {
    expect(secretSourceLabel('urlscan', null)).toBe('urlscan history')
    expect(secretSourceLabel('url_archive', null)).toBe('web archives')
    expect(secretSourceLabel('jsluice', null)).toBe('jsluice')
  })

  test('the route reads a Secret on a Subdomain or Domain with its masked URL', async () => {
    const fields: Record<string, unknown> = {
      nodeId: '1', id: 'secret-urlscan-x', secretType: 'api_key', valueSample: null, sourceModule: 'urlscan',
      maskedUrl: 'https://app.example.test/api?apikey=***', valueLength: 32,
      subdomain: 'app.example.test', origin: 'Secret', severity: 'high',
    }
    mockRun.mockResolvedValue({ records: [] })
    mockRun.mockResolvedValueOnce({ records: [{ get: (k: string) => fields[k] ?? null }] })
    const { GET } = await import('@/app/api/analytics/redzone/secrets/route')
    const res = await GET({ nextUrl: new URL('http://x/api?projectId=p1') } as never)
    const cypher = String(mockRun.mock.calls[0][0])
    expect(cypher).toContain('OPTIONAL MATCH (hostNode)-[:HAS_SECRET]->(s) WHERE hostNode:Subdomain OR hostNode:Domain')
    const body = await res.json()
    const row = body.rows.find((r: { id: string }) => r.id === 'secret-urlscan-x')
    expect(row.sourceModule).toBe('urlscan history')
    expect(row.maskedUrl).toBe('https://app.example.test/api?apikey=***')
    expect(row.valueLength).toBe(32)
    expect(row.subdomain).toBe('app.example.test')
  })

  test('the route returns the full value and the full link, which the Source URL opens', async () => {
    const fields: Record<string, unknown> = {
      nodeId: '2', id: 'secret-urlscan-y', secretType: 'api_key', valueSample: null, sourceModule: 'urlscan',
      maskedUrl: 'https://app.example.test/api?apikey=***', valueLength: 24,
      secretValue: 'ak9Q2w8E3r7T4y6U1i0O5pLz',
      unmaskedUrl: 'https://app.example.test/api?apikey=ak9Q2w8E3r7T4y6U1i0O5pLz',
      subdomain: 'app.example.test', origin: 'Secret', severity: 'high',
    }
    mockRun.mockReset()
    mockRun.mockResolvedValue({ records: [] })
    mockRun.mockResolvedValueOnce({ records: [{ get: (k: string) => fields[k] ?? null }] })
    const { GET } = await import('@/app/api/analytics/redzone/secrets/route')
    const res = await GET({ nextUrl: new URL('http://x/api?projectId=p1') } as never)
    const cypher = String(mockRun.mock.calls[0][0])
    expect(cypher).toContain('coalesce(s.secret_value, s.matched_text)  AS secretValue')
    expect(cypher).toContain('s.unmasked_url                            AS unmaskedUrl')
    const row = (await res.json()).rows.find((r: { id: string }) => r.id === 'secret-urlscan-y')
    expect(row.secretValue).toBe('ak9Q2w8E3r7T4y6U1i0O5pLz')
    expect(row.sourceUrl).toBe('https://app.example.test/api?apikey=ak9Q2w8E3r7T4y6U1i0O5pLz')
    expect(row.maskedUrl).toBe('https://app.example.test/api?apikey=***')
  })

  test('the table shows a masked secret as masked, with its length', () => {
    const table = readFileSync(resolve(__dirname, '../../app/graph/components/RedZoneTables/SecretsTable.tsx'), 'utf8')
    expect(table).toContain('masked</span>')
    expect(table).toContain('chars')
  })
})
