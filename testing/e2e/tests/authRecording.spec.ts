import { test, expect, type APIRequestContext, type PlaywrightWorkerArgs } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * Authenticated Session Recording, driven through the real UI against the real
 * stack and a real target (testing/guinea_pigs/auth_target).
 *
 * Unit suites cover the builder, the extractor and each route in isolation. Only
 * this run proves the whole chain holds together: the operator clicks Record in
 * the browser, a real login flows through the capture proxy, the ingest worker
 * extracts it before redaction, and the profile comes back to the browser with
 * the secret stripped.
 *
 * Requires: stack up, and `cd testing/guinea_pigs/auth_target && docker compose up -d --build`.
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const PROXY = process.env.REDAMON_CAPTURE_PROXY || 'http://127.0.0.1:8888'
// Deliberately a SUBDOMAIN: the recording scope must cover it via *.root, not
// just the apex.
//
// 9010 is BOTH the pig's published port and its in-container port, and they are
// kept equal on purpose. This request is proxied, and the capture proxy sits on
// pentest-net where the alias resolves to the container IP, so the port that
// works from the host must also be open inside the network.
const TARGET = 'http://app.authpig.test:9010'

let projectId = ''
let api: APIRequestContext | undefined
let pigUp = false

const PIG_HINT = `guinea pig not reachable at ${TARGET}. Start it with: `
  + 'cd testing/guinea_pigs/auth_target && docker compose up -d --build'

test.beforeAll(async ({ playwright, baseURL }) => {
  // The guinea pig is a separate compose project that is often not running.
  // Without this the suite dies deep inside the recording flow on "target did
  // not issue a session cookie", which reads like a product bug rather than a
  // missing prerequisite. Record the verdict and skip per-test in beforeEach:
  // a test.skip() thrown from beforeAll leaves the rest of the group running
  // against an unset projectId.
  const probe = await playwright.request.newContext({ ignoreHTTPSErrors: true })
  pigUp = await probe.get(`${TARGET}/healthz`, { timeout: 5_000 })
    .then(r => r.ok()).catch(() => false)
  await probe.dispose()
  if (!pigUp) return

  api = await playwright.request.newContext({
    baseURL,
    extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api!.post('/api/projects', {
    data: {
      name: `e2e-auth-recording-${Date.now()}`,
      targetDomain: 'authpig.test',
      captureProxyEnabled: true,
    },
  })
  expect(res.ok(), `could not create project: ${res.status()} ${await res.text()}`).toBeTruthy()
  projectId = (await res.json()).id
  expect(projectId, 'project id missing from create response').toBeTruthy()
})

test.afterAll(async () => {
  if (!api) return
  if (projectId) await api.delete(`/api/projects/${projectId}`)
  await api.dispose()
})

test.beforeEach(async ({ context, baseURL }) => {
  test.skip(!pigUp, PIG_HINT)
  await signIn(context, USER, baseURL!)
  await context.addInitScript(([pid, uid]) => {
    localStorage.setItem('redamon-current-project', pid)
    localStorage.setItem('redamon-current-user', uid)
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  }, [projectId, USER])
})

/** Log in to the guinea pig THROUGH the capture proxy, as the operator's browser would. */
async function loginThroughProxy(playwright: PlaywrightWorkerArgs['playwright']) {
  const proxied = await playwright.request.newContext({
    proxy: { server: PROXY },
    ignoreHTTPSErrors: true,
  })
  const login = await proxied.post(`${TARGET}/login`, {
    form: { username: 'operator', password: 'hunter2', csrf_token: 'csrf-authpig-789' },
    maxRedirects: 0,
  })
  const setCookie = login.headers()['set-cookie'] || ''
  expect(setCookie, 'target did not issue a session cookie').toContain('authpig_session')
  const cookie = setCookie.split(';')[0]
  // A couple of authenticated follow-ups, so the recording sees steady-state
  // traffic carrying the session and not only the login response.
  await proxied.get(`${TARGET}/dashboard`, { headers: { cookie } })
  await proxied.get(`${TARGET}/whoami`, { headers: { cookie } })
  await proxied.dispose()
  return cookie
}

test('operator records a login in the UI and the profile is saved write-only', async ({ page, playwright }) => {
  // 1. Open the recording modal from the project's Authenticated Session section
  //    (recording now lives there, not on /traffic).
  await page.goto(`/projects/${projectId}/settings`)
  await page.getByText('Target Input', { exact: false }).first().click()
  await page.getByText('Authenticated Session').click()
  await page.getByRole('button', { name: /Record login/i }).click()
  await expect(page.getByRole('button', { name: 'Start recording' })).toBeVisible()

  // 2. Start recording.
  await page.getByRole('button', { name: 'Start recording' }).click()
  await expect(page.getByText(/Recording/)).toBeVisible()

  // 3+4. Drive real logins through the proxy until the observed counter moves.
  //
  // The retry is not flake-padding, it is the documented shape of the feature:
  // the webapp emits `active_recording` into the capture-config, which the
  // orchestrator reconciles to the proxy's config file on a ~5s loop. So the
  // proxy starts tagging up to one interval AFTER the modal says "Recording",
  // and traffic sent inside that window is untagged and correctly rejected at
  // ingest. An operator browses for a while; this mirrors that.
  await expect.poll(async () => {
    await loginThroughProxy(playwright)
    const r = await api.get(`/api/projects/${projectId}/recording/status`)
    return r.ok() ? (await r.json()).session?.observedCount ?? 0 : 0
  }, {
    timeout: 60_000,
    intervals: [2_000],
    message: 'no operator traffic was ever observed through the capture proxy',
  }).toBeGreaterThan(0)

  // 5. Stop, and confirm the masked summary names what was captured.
  await page.getByRole('button', { name: 'Stop' }).click()
  await expect(page.getByText('Cookie set')).toBeVisible()

  // 6. Save it into the project's auth profile.
  await page.getByRole('button', { name: 'Save session' }).click()
  await expect(page.getByRole('button', { name: 'Save session' })).toBeHidden()

  // 7. The browser view of the project must carry metadata only. This is the
  //    write-only boundary, asserted against the real serialised response.
  const projRes = await api.get(`/api/projects/${projectId}`)
  const raw = await projRes.text()
  expect(raw).not.toContain('authpig-session-COOKIEVALUE')
  const proj = JSON.parse(raw)
  expect(proj.authProfile).toMatchObject({ authType: 'cookie', source: 'recorded', hasValue: true })
  expect(proj.authProfile).not.toHaveProperty('authValue')
  expect(proj.authProfile).not.toHaveProperty('extraHeaders')
})

test('an empty recording never overwrites the saved profile', async ({ page }) => {
  // The profile from the previous test is still stored. Record nothing at all
  // and confirm the operator is told, and that the stored session survives.
  await page.goto(`/projects/${projectId}/settings`)
  await page.getByText('Target Input', { exact: false }).first().click()
  await page.getByText('Authenticated Session').click()
  await page.getByRole('button', { name: /Record login/i }).click()
  await page.getByRole('button', { name: 'Start recording' }).click()
  await expect(page.getByText(/Recording/)).toBeVisible()
  await page.getByRole('button', { name: 'Stop' }).click()

  await expect(page.getByText(/No login detected/i)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save session' })).toHaveCount(0)

  const proj = await (await api.get(`/api/projects/${projectId}`)).json()
  expect(proj.authProfile?.hasValue, 'the stored profile was destroyed by an empty capture').toBe(true)
})
