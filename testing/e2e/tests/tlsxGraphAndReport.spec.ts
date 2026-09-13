import { test, expect } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * The two read paths for certificates: the graph page and the report.
 *
 * Both have unit tests over mocked rows, and neither had ever rendered real
 * scan output. That gap matters here because these queries anchor certificates
 * on `(:IP)-[:HAS_CERTIFICATE]->` -- the anchor Phase 0 added -- and a
 * certificate that exists but is not anchored renders as an empty section that
 * looks like "no findings" rather than a broken query.
 *
 * Needs a project whose graph actually holds certificates. Run:
 *   cd testing/e2e && npx playwright test tlsxGraphAndReport
 */

const PROJECT = process.env.REDAMON_PROJECT || '3a2435862fc24f2eaf71062fc'
const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'

const cookie = () => ({ cookie: `redamon-auth=${mintToken(USER)}` })

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

test('the graph API returns the certificates with their posture', async ({ request, baseURL }) => {
  const res = await request.get(`${baseURL}/api/graph?projectId=${PROJECT}`, { headers: cookie() })
  expect(res.ok(), `GET /api/graph -> ${res.status()}`).toBeTruthy()
  const body = await res.json()
  const nodes: any[] = body.nodes || body.data?.nodes || []
  expect(nodes.length, 'the graph came back empty').toBeGreaterThan(0)

  const certs = nodes.filter(n =>
    (n.labels || [n.type]).some((l: string) => l === 'Certificate'))
  expect(certs.length, 'no Certificate node reached the graph payload').toBe(4)

  const cns = certs.map(c => (c.properties || c).subject_cn).sort()
  expect(cns).toEqual([
    '*.wild.tlslab.test', 'ldap.tlslab.test', 'legacy.tlslab.test', 'mail.tlslab.test',
  ])

  // The posture fields the tables and the report read.
  const expired = certs.filter(c => (c.properties || c).expired === true)
  expect(expired.length, 'the expired certificate lost its flag in transit').toBe(1)
})

test('the graph page renders a certificate from real scan data', async ({ page }) => {
  await page.goto(`/graph?project=${PROJECT}&table=all`)
  // The table is the deterministic surface; the canvas is a WebGL render.
  await expect(page.getByText('mail.tlslab.test', { exact: false }).first())
    .toBeVisible({ timeout: 30_000 })
})

test('a generated report carries the TLS posture section', async ({ request, baseURL }) => {
  const created = await request.post(
    `${baseURL}/api/projects/${PROJECT}/reports`,
    { headers: { ...cookie(), 'content-type': 'application/json' }, data: {} })
  expect(created.status(), await created.text()).toBe(201)
  const { id } = await created.json()

  const doc = await request.get(`${baseURL}/api/projects/${PROJECT}/reports/${id}`,
                                { headers: cookie() })
  expect(doc.ok()).toBeTruthy()
  const html = await doc.text()
  // The counts are wrapped in markup, so assert on the rendered text.
  const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ')

  expect(html, 'the TLS section is missing entirely').toContain('TLS Certificate Posture')
  // Counts, not just presence: an anchor regression yields "Observed 0".
  expect(text).toMatch(/Observed 4 TLS certificate\(s\)/)
  expect(text).toMatch(/1 expired/)
  expect(text).toMatch(/4 self-signed/)
  expect(text).toMatch(/1 wildcard/)
  // H5: dialling a bare IP is not a mismatch, and the report must agree.
  expect(text).toMatch(/0 hostname-mismatched/)
  for (const cn of ['mail.tlslab.test', 'ldap.tlslab.test',
                    'legacy.tlslab.test', '*.wild.tlslab.test']) {
    expect(html, `${cn} missing from the report`).toContain(cn)
  }
})
