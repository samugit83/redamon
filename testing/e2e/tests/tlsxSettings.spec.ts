import { test, expect, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * Every tlsx setting, driven through the real settings UI and verified twice:
 * in the PUT the form actually sends, and by reading the row back.
 *
 * Why a browser test for a settings form: a RedAmon setting spans five layers
 * (Prisma column, the Python defaults dict, the fetch mapping, /defaults, and
 * the form's onChange). A mismatch in any one leaves the control visibly
 * working while the value never reaches the database, and no unit test in
 * either language sees it. Four tlsx toggles read back false from Postgres
 * after two saves from the UI, which is what this spec exists to settle.
 *
 * The page opens in Workflow view, so both routes to the same section are
 * covered: the Tab view form and the gear on the TLS Grab node.
 *
 * Requires the stack up and the webapp image built. Run:
 *   cd testing/e2e && npx playwright test tlsxSettings
 */

const PROJECT = process.env.REDAMON_PROJECT || '3a2435862fc24f2eaf71062fc'
const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'

/** Label text -> Prisma field, for the "Deeper probes (louder OPSEC)" block. */
const PROBES: Record<string, string> = {
  'JARM / JA3 fingerprints': 'tlsxProbeJarm',
  'Enumerate supported TLS versions': 'tlsxVersionEnum',
  'Enumerate weak ciphers': 'tlsxCipherEnum',
  'Reverse-PTR SNI for bare IPs': 'tlsxRevPtrSni',
}

/** Every tlsx field the section exposes, at a value that differs from default. */
const NON_DEFAULT: Record<string, unknown> = {
  tlsxEnabled: true,
  tlsxInjectHostnames: false,
  tlsxIncludeHttpPorts: true,
  tlsxConcurrency: 33,
  tlsxTimeout: 9,
  tlsxMaxTargets: 1234,
  tlsxMaxInjectedHostnames: 42,
  tlsxProbeJarm: true,
  tlsxVersionEnum: true,
  tlsxCipherEnum: true,
  tlsxRevPtrSni: true,
}

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

async function readRow(request: any, baseURL: string): Promise<Record<string, unknown>> {
  const res = await request.get(`${baseURL}/api/projects/${PROJECT}`, { headers: cookie() })
  expect(res.ok(), `GET project -> ${res.status()}`).toBeTruthy()
  return await res.json()
}

/** Reset the probes to false so a rerun starts from a known state. */
async function resetProbes(request: any, baseURL: string) {
  const row = await readRow(request, baseURL)
  const res = await request.put(`${baseURL}/api/projects/${PROJECT}`, {
    headers: { ...cookie(), 'content-type': 'application/json' },
    data: {
      ...row,
      tlsxProbeJarm: false, tlsxVersionEnum: false,
      tlsxCipherEnum: false, tlsxRevPtrSni: false,
    },
  })
  expect(res.ok(), `reset PUT -> ${res.status()}`).toBeTruthy()
}

/** The switch belonging to a labelled toggle row: label -> row -> switch. */
function toggleFor(scope: Page | any, label: string) {
  return scope.getByText(label, { exact: true }).first()
    .locator('xpath=../..').getByRole('switch').first()
}

async function openSettings(page: Page) {
  await page.goto(`/projects/${PROJECT}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
}

/**
 * Tab view renders the sections as a plain form. tlsx lives under the Port
 * Scanning tab, because it consumes the ports the port scan found.
 */
async function openTlsxViaTabView(page: Page) {
  await openSettings(page)
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: 'Port Scanning', exact: true }).first().click()
  const header = page.getByText('TLS Certificate Grab', { exact: false }).first()
  await header.waitFor({ state: 'visible', timeout: 20_000 })
  if (!(await page.getByText('Deeper probes', { exact: false }).first()
                  .isVisible().catch(() => false))) {
    await header.click()
  }
  await expect(page.getByText('Deeper probes', { exact: false }).first()).toBeVisible()
  return page
}

/**
 * The gear on the TLS Grab node opens the same section in a modal. Its save
 * button carries the same "Update Settings" label as the page's, so everything
 * here is scoped to the overlay: an unscoped locator resolves to the button
 * behind it, which the overlay then blocks.
 */
async function openTlsxViaWorkflowGear(page: Page) {
  await openSettings(page)
  const node = page.locator('div').filter({ hasText: /^TLS Grab/ }).last()
  await node.waitFor({ state: 'visible', timeout: 20_000 })
  await node.locator('[class*="settingsIcon"]').first().click()
  const modal = page.locator('[class*="overlay"]').first()
  await expect(modal.getByText('Deeper probes', { exact: false }).first())
    .toBeVisible({ timeout: 15_000 })
  return modal
}

test('the section exposes every tlsx control', async ({ page }) => {
  await openTlsxViaTabView(page)
  for (const label of ['Coverage', 'Concurrency', 'Handshake timeout',
                       'Max targets', 'Max SAN hostnames injected',
                       'Deeper probes', ...Object.keys(PROBES)]) {
    await expect(page.getByText(label, { exact: false }).first(),
                 `control missing: ${label}`).toBeVisible()
  }
})

for (const [routeName, open] of [
  ['tab view', openTlsxViaTabView],
  ['workflow gear', openTlsxViaWorkflowGear],
] as const) {
  test(`the deeper-probe toggles persist from the ${routeName}`, async ({ page, request, baseURL }) => {
    await resetProbes(request, baseURL!)
    const scope = await open(page)

    const sent: Record<string, unknown>[] = []
    page.on('request', req => {
      if (req.method() === 'PUT' && req.url().includes(`/api/projects/${PROJECT}`)) {
        try { sent.push(req.postDataJSON()) } catch { /* non-JSON */ }
      }
    })

    for (const label of Object.keys(PROBES)) {
      const sw = toggleFor(scope, label)
      await expect(sw, `no switch for "${label}"`).toBeVisible()
      await expect(sw, `"${label}" did not start off`).toHaveAttribute('aria-checked', 'false')
      await sw.click()
      await expect(sw, `"${label}" did not flip in the UI`).toHaveAttribute('aria-checked', 'true')
    }

    // Exact name on purpose: a loose /^Save/ matches "Save as Preset", which
    // sits earlier in the DOM, and clicking it opens the preset dialog while
    // the project is never saved -- a green-looking click that does nothing.
    const save = scope.getByRole('button', { name: 'Update Settings', exact: true }).first()
    await expect(save, 'Save stayed disabled, so the form never saw the change').toBeEnabled()

    // Wait for the RESPONSE, not the request: reading the row back while the
    // PUT is still in flight reports the old value and looks exactly like a
    // column that does not persist.
    const [response] = await Promise.all([
      page.waitForResponse(r =>
        r.request().method() === 'PUT' &&
        r.url().includes(`/api/projects/${PROJECT}`), { timeout: 20_000 }),
      save.click(),
    ])
    expect(response.status(), `PUT -> ${response.status()}`).toBeLessThan(400)

    expect(sent.length, 'no PUT was captured').toBeGreaterThan(0)
    const body = sent[sent.length - 1]
    for (const field of Object.values(PROBES)) {
      expect(body, `the form never sent ${field}`).toHaveProperty(field)
      expect(body[field], `${field} left the form as ${body[field]}`).toBe(true)
    }

    const row = await readRow(request, baseURL!)
    for (const field of Object.values(PROBES)) {
      expect(row[field], `${field} did not persist`).toBe(true)
    }
  })
}

test('every tlsx field round-trips through the API at a non-default value', async ({ request, baseURL }) => {
  // Isolates the column and the route from the form's own state handling.
  const before = await readRow(request, baseURL!)
  const res = await request.put(`${baseURL}/api/projects/${PROJECT}`, {
    headers: { ...cookie(), 'content-type': 'application/json' },
    data: { ...before, ...NON_DEFAULT },
  })
  expect(res.ok(), `PUT -> ${res.status()} ${await res.text()}`).toBeTruthy()

  const after = await readRow(request, baseURL!)
  for (const [field, want] of Object.entries(NON_DEFAULT)) {
    expect(after[field], `${field} did not round-trip`).toBe(want)
  }
})
