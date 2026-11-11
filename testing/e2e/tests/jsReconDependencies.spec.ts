import { execFileSync } from 'node:child_process'
import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * S-19: the JS Recon table's Dependencies tab shows each dependency-confusion
 * finding's Scope and "On npm?" as the writer stores them: `package_scope`, and
 * `npm_exists` true -> "Yes", false -> "No", absent (a node written before the
 * field, or a lookup that never answered) -> "-", never "No".
 *
 * Before S-19 the writer stored neither field and the tab printed "No" for every
 * row, the "exists on npm but marked internal" one included, with Scope empty.
 *
 * The three nodes, and the js_file node a run writes for the bundle importing
 * them (the table answers "no data" without one), are seeded straight into a
 * throwaway project's graph: a JS
 * Recon run decides npm_exists by asking the public npm registry, and the FP
 * lab sends nothing off the host. The writer side (js_recon_mixin's dependency
 * branch) is covered by its unit and live-graph tests. Checked at full width and
 * at 390 px. Run:
 *   cd testing/e2e && npx playwright test jsReconDependencies
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const NEO4J = process.env.REDAMON_NEO4J_CONTAINER || 'redamon-neo4j'

const ROWS = [
  { pkg: '@fplab-internal/billing-core', scope: '@fplab-internal', npm: 'No' },
  { pkg: '@fplab-shared/ui-kit', scope: '@fplab-shared', npm: 'Yes' },
  { pkg: '@fplab-legacy/old-sdk', scope: '@fplab-legacy', npm: '-' },
]

const SEED = `
UNWIND $rows AS r
CREATE (f:JsReconFinding {
  id: r.id, user_id: $uid, project_id: $pid, finding_type: 'dependency_confusion',
  source: 'js_recon', package_name: r.pkg, severity: r.sev, confidence: 'high',
  title: r.title, detail: r.title, source_url: 'http://192.88.94.20/js/deps.js',
  source_urls: ['http://192.88.94.20/js/deps.js'], updated_at: datetime()})
FOREACH (_ IN CASE WHEN r.legacy THEN [] ELSE [1] END |
  SET f.package_scope = r.scope, f.npm_exists = r.npm, f.recommendation = r.rec)
WITH count(f) AS seeded
CREATE (:JsReconFinding {
  id: 'e2e-depconf-file', user_id: $uid, project_id: $pid, finding_type: 'js_file', source: 'js_recon',
  severity: 'info', title: 'deps.js', source_url: 'http://192.88.94.20/js/deps.js',
  base_url: 'http://192.88.94.20', updated_at: datetime()})
`

/** Cypher inside the Neo4j container: the password stays in its NEO4J_AUTH. */
function cypher(query: string, params: Record<string, unknown>) {
  const literal = (v: unknown): string => Array.isArray(v)
    ? `[${v.map(literal).join(', ')}]`
    : v !== null && typeof v === 'object'
      ? `{${Object.entries(v).map(([k, x]) => `${k}: ${literal(x)}`).join(', ')}}`
      : JSON.stringify(v)
  const args = Object.entries(params).flatMap(([k, v]) => ['-P', `${k} => ${literal(v)}`])
  execFileSync('docker', ['exec', '-i', NEO4J, 'sh', '-c',
    'cypher-shell -u neo4j -p "${NEO4J_AUTH#neo4j/}" --format plain "$@"', 'sh', ...args],
  { input: query, encoding: 'utf8', timeout: 60_000 })
}

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: {
      name: 'e2e js recon dependencies (temp)', ipMode: true, targetIps: ['192.88.94.34'],
      engagementKind: 'internal', targetGuardrailEnabled: false,
    },
  })
  expect(res.ok(), `create project: ${res.status()} ${await res.text()}`).toBeTruthy()
  projectId = (await res.json()).id
  cypher(SEED, {
    uid: USER, pid: projectId,
    rows: ROWS.map((r, i) => ({
      id: `e2e-depconf-${i}`, pkg: r.pkg, scope: r.scope, legacy: r.npm === '-',
      npm: r.npm === 'Yes', sev: r.npm === 'Yes' ? 'high' : 'critical',
      title: `Dependency confusion: ${r.pkg}`, rec: `Verify npm ownership of ${r.pkg}.`,
    })),
  })
})

test.afterAll(async () => {
  if (projectId) {
    cypher('MATCH (f:JsReconFinding {user_id: $uid, project_id: $pid}) DETACH DELETE f',
      { uid: USER, pid: projectId })
    const res = await api.delete(`/api/projects/${projectId}`)
    expect(res.ok(), `delete the throwaway project: ${res.status()}`).toBeTruthy()
  }
  await api?.dispose()
})

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

async function openDependencies(page: Page) {
  await page.goto(`/graph?project=${projectId}&table=jsRecon`)
  await page.getByRole('button', { name: /^Dependencies/ }).first().click({ timeout: 30_000 })
  await expect(page.locator('table').getByText('On npm?')).toBeVisible({ timeout: 20_000 })
}

for (const [width, height] of [[1600, 1000], [390, 844]] as const) {
  test(`Scope and On npm? per stored field at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    await openDependencies(page)
    const headers = await page.locator('table thead th').allInnerTexts()
    // innerText carries the header's CSS uppercase.
    const col = (name: string) => headers.findIndex(h => h.trim().toLowerCase() === name.toLowerCase())
    expect(col('Scope'), `headers: ${headers}`).toBeGreaterThan(-1)
    expect(col('On npm?'), `headers: ${headers}`).toBeGreaterThan(-1)
    for (const want of ROWS) {
      const row = page.locator('table tbody tr', { hasText: want.pkg })
      await expect(row, `no row for ${want.pkg}`).toHaveCount(1)
      const cells = await row.locator('td').allInnerTexts()
      expect(cells[col('Scope')].trim(), `${want.pkg} Scope`).toBe(want.scope)
      expect(cells[col('On npm?')].trim(), `${want.pkg} On npm?`).toBe(want.npm)
    }
  })
}
