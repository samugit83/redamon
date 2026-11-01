/**
 * A failed JS Recon read answers a fixed sentence and the Neo4j code, never the
 * driver's message, which can quote the Cypher and the project's target data.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/js-recon/[projectId]/download/route.test.ts"
 * @vitest-environment node
 */
import { test, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ run: vi.fn(), close: vi.fn() }))

vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: h.run, close: h.close }) }))

import { GET } from './route'

const records = (rows: Record<string, unknown>[]) => ({
  records: rows.map(row => ({ get: (key: string) => (key in row ? row[key] : null) })),
})

/** Answer the Secret query with `secrets`, every other query with nothing. */
function graphWithSecrets(secrets: Record<string, unknown>[]) {
  h.run.mockImplementation(async (cypher: string) => (/MATCH \(s:Secret/.test(cypher) ? records(secrets) : records([])))
}

async function download() {
  const res = await GET(new NextRequest('http://localhost/api/js-recon/p1/download?fresh=1'), { params: Promise.resolve({ projectId: 'p1' }) })
  expect(res.status).toBe(200)
  return res.json()
}

test('a Neo4j failure answers its code, not its message', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.run.mockRejectedValue(Object.assign(
    new Error('Database unavailable while running MATCH (jf:JsReconFinding {project_id: "p1"}) secret-target.example'),
    { code: 'Neo.TransientError.General.DatabaseUnavailable', name: 'Neo4jError' },
  ))
  const res = await GET(new NextRequest('http://localhost/api/js-recon/p1/download?fresh=1'), { params: Promise.resolve({ projectId: 'p1' }) })
  expect(res.status).toBe(500)
  const body = await res.json()
  expect(body).toEqual({ error: 'JS Recon query failed', code: 'Neo.TransientError.General.DatabaseUnavailable' })
  expect(h.close).toHaveBeenCalled()
})

test('the Secret query reads the line and the alternate names', async () => {
  graphWithSecrets([])
  await GET(new NextRequest('http://localhost/api/js-recon/p1/download?fresh=1'), { params: Promise.resolve({ projectId: 'p1' }) })
  const cypher = h.run.mock.calls.map(c => String(c[0])).find(c => /MATCH \(s:Secret/.test(c))!
  expect(cypher).toMatch(/s\.line_number AS line_number/)
  expect(cypher).toMatch(/s\.alternate_names AS alternate_names/)
  expect(cypher).toMatch(/s\.detection_method AS detection_method/)
})

test('a TruffleHog-only secret arrives with its detection, line and names', async () => {
  graphWithSecrets([{
    nodeId: '11', id: 's1', name: 'GitHub Token Classic', severity: 'high', detection_method: 'trufflehog',
    line_number: { low: 42, high: 0 }, alternate_names: [], validation_status: 'unknown', updatedAt: 't1',
  }, {
    nodeId: '12', id: 's2', name: 'Stripe Secret Key', severity: 'critical', detection_method: 'regex',
    line_number: 7, alternate_names: ['Generic API Key', 'TruffleHog:Stripe'], validation_status: 'rejected', updatedAt: 't2',
  }])
  const body = await download()
  expect(body.secrets).toHaveLength(2)
  expect(body.secrets[0]).toMatchObject({ detection_method: 'trufflehog', line_number: 42, alternate_names: [] })
  expect(body.secrets[1]).toMatchObject({ detection_method: 'regex', line_number: 7, alternate_names: ['Generic API Key', 'TruffleHog:Stripe'] })
})

test('a node written before the properties answers null for both', async () => {
  graphWithSecrets([{ nodeId: '13', id: 's3', name: 'AWS Access Key ID', severity: 'critical', updatedAt: 't3' }])
  const body = await download()
  expect(body.secrets[0].line_number).toBeNull()
  expect(body.secrets[0].alternate_names).toBeNull()
})
