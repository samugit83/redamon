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

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
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

/** Answer the JsReconFinding query with `findings`, every other query with nothing. */
function graphWithFindings(findings: Record<string, unknown>[]) {
  h.run.mockImplementation(async (cypher: string) => (/MATCH \(jf:JsReconFinding/.test(cypher) && !/HAS_ENDPOINT/.test(cypher) ? records(findings) : records([])))
}

const JS_FILE = { nodeId: '1', id: 'f1', findingType: 'js_file', sourceUrl: 'https://app.example.com/main.js', updatedAt: 't0' }

// The writer stores every importing file in `source_urls` and the package in
// `package_name` (R-49); the route answered neither, so the Dependencies export
// had no sources and the Package column showed the finding's title.
const DEPENDENCY = {
  nodeId: '21', id: 'd1', findingType: 'dependency_confusion', severity: 'high',
  title: 'Dependency confusion: @acme/internal-ui not on public npm', packageName: '@acme/internal-ui',
  sourceUrl: 'https://app.example.com/main.js',
  sourceUrls: ['https://app.example.com/main.js', 'https://app.example.com/vendor.js'], updatedAt: 't1',
}

test('a dependency finding answers its package name and every file that imports it', async () => {
  graphWithFindings([JS_FILE, DEPENDENCY])
  const body = await download()
  expect(body.dependencies).toHaveLength(1)
  expect(body.dependencies[0]).toMatchObject({
    package_name: '@acme/internal-ui',
    source_url: 'https://app.example.com/main.js',
    source_urls: ['https://app.example.com/main.js', 'https://app.example.com/vendor.js'],
  })
  const cypher = h.run.mock.calls.map(c => String(c[0])).find(c => /MATCH \(jf:JsReconFinding/.test(c) && !/HAS_ENDPOINT/.test(c))!
  expect(cypher).toMatch(/coalesce\(jf\.source_urls, \[jf\.source_url\]\) AS sourceUrls/)
  expect(cypher).toMatch(/jf\.package_name AS packageName/)
})

test('a dependency node written before those properties falls back to its source_url and title', async () => {
  graphWithFindings([JS_FILE, {
    nodeId: '22', id: 'd2', findingType: 'dependency_confusion', title: 'Dependency confusion: @acme/old not on public npm',
    sourceUrl: '', sourceUrls: [''], updatedAt: 't2',
  }, {
    nodeId: '23', id: 'd3', findingType: 'dependency_confusion', title: '@acme/legacy',
    sourceUrl: 'https://app.example.com/legacy.js', sourceUrls: ['https://app.example.com/legacy.js'], updatedAt: 't3',
  }])
  const body = await download()
  expect(body.dependencies[0]).toMatchObject({ package_name: 'Dependency confusion: @acme/old not on public npm', source_urls: [] })
  expect(body.dependencies[1]).toMatchObject({ package_name: '@acme/legacy', source_urls: ['https://app.example.com/legacy.js'] })
})

// The writer stores the npm scope as `package_scope` beside `package_name`, and
// the registry's answer in `npm_exists` (S-19); the route answered neither, so
// the Dependencies table read "On npm? No" on every row and an empty Scope.
test('a dependency finding answers its scope, npm answer and recommendation', async () => {
  graphWithFindings([JS_FILE, {
    ...DEPENDENCY, packageScope: '@acme', npmExists: false,
    recommendation: 'Register @acme/internal-ui on npm as a placeholder or use a private registry.',
  }, {
    nodeId: '24', id: 'd4', findingType: 'dependency_confusion', severity: 'high',
    title: 'Potential dependency confusion: @acme/billing-core exists on npm but marked as internal',
    packageName: '@acme/billing-core', packageScope: '@acme', npmExists: true,
    recommendation: 'Verify npm ownership of @acme/billing-core.', sourceUrls: ['custom_packages_file'], updatedAt: 't4',
  }])
  const body = await download()
  expect(body.dependencies[0]).toMatchObject({
    scope: '@acme', npm_exists: false,
    recommendation: 'Register @acme/internal-ui on npm as a placeholder or use a private registry.',
  })
  expect(body.dependencies[1]).toMatchObject({
    package_name: '@acme/billing-core', scope: '@acme', npm_exists: true,
    recommendation: 'Verify npm ownership of @acme/billing-core.',
  })
  const cypher = h.run.mock.calls.map(c => String(c[0])).find(c => /MATCH \(jf:JsReconFinding/.test(c) && !/HAS_ENDPOINT/.test(c))!
  expect(cypher).toMatch(/jf\.package_scope AS packageScope/)
  expect(cypher).toMatch(/jf\.npm_exists AS npmExists/)
  expect(cypher).toMatch(/jf\.recommendation AS recommendation/)
})

test('a dependency node written before those properties answers npm_exists unknown, never false', async () => {
  graphWithFindings([JS_FILE, DEPENDENCY, {
    nodeId: '25', id: 'd5', findingType: 'dependency_confusion', title: 'Dependency confusion: billing-core not on public npm',
    packageName: 'billing-core', sourceUrls: ['custom_packages_file'], updatedAt: 't5',
  }])
  const body = await download()
  // The scope comes from the package name; an unscoped package has none.
  expect(body.dependencies[0]).toMatchObject({ scope: '@acme', npm_exists: null, recommendation: null })
  expect(body.dependencies[1]).toMatchObject({ scope: null, npm_exists: null, recommendation: null })
})

// The browser revalidates its cached body by this tag alone. The one below is
// what the route answered for this graph before it returned the dependency
// fields; a 304 to it would keep a pre-upgrade body, sources missing, until the
// graph next changed.
test('a body cached before the dependency fields were answered is not revalidated as current', async () => {
  const before = '"e683b0d0e021459f"'
  graphWithFindings([JS_FILE, DEPENDENCY])
  const res = await GET(
    new NextRequest('http://localhost/api/js-recon/p1/download?fresh=1', { headers: { 'if-none-match': before } }),
    { params: Promise.resolve({ projectId: 'p1' }) },
  )
  expect(res.status).toBe(200)
  expect(res.headers.get('ETag')).not.toBe(before)
})

// The tag this graph answered before the scope and npm answer were returned: a
// 304 to it would keep a body whose every row reads "On npm? No".
test('a body cached before the scope and npm answer were answered is not revalidated as current', async () => {
  const before = '"aaf1f2a081badad0"'
  graphWithFindings([JS_FILE, DEPENDENCY])
  const res = await GET(
    new NextRequest('http://localhost/api/js-recon/p1/download?fresh=1', { headers: { 'if-none-match': before } }),
    { params: Promise.resolve({ projectId: 'p1' }) },
  )
  expect(res.status).toBe(200)
  expect(res.headers.get('ETag')).not.toBe(before)
})
