import { test, expect, type Page } from '@playwright/test'
import { signIn } from './auth'

/**
 * Plan 12.5: Resume re-checks the Rules of Engagement time window. Outside it
 * the orchestrator answers 403, the scan stays paused, and the graph page says
 * so instead of failing silently, on a desktop and on a 390 px screen.
 *
 * The recon status (paused) and the resume answer are served by the test, so
 * the refusal is on screen whatever the project's window says. The check
 * itself is covered by recon_orchestrator/tests/test_pause_resume.py and the
 * nested-wildcard lab run (plan 12.E).
 *
 * Requires the stack to be up. Run: npx playwright test resumeRefusal
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const REFUSAL = 'RoE time window: current time 18:05 UTC is outside allowed window (09:00-18:00)'
// graph/page.tsx: readApiError adds the HTTP status to the orchestrator's reason.
const TOAST = `Resume failed: ${REFUSAL} (HTTP 403). The scan stays paused.`

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

async function pausedGraph(page: Page) {
  const projects = await (await page.request.get('/api/projects')).json()
  const project: string = process.env.REDAMON_PROJECT || projects[0]?.id
  test.skip(!project, 'this user has no project to open')
  const resumes: string[] = []
  await page.route(`**/api/recon/${project}/status`, route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      project_id: project, status: 'paused', current_phase: 'Vulnerability Scanning', phase_number: 5,
      total_phases: 6, started_at: '2026-10-27T08:00:00Z', completed_at: null, error: null,
    }) }))
  await page.route(`**/api/recon/${project}/resume`, route => {
    resumes.push(route.request().method())
    return route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: REFUSAL }) })
  })
  await page.goto(`/graph?project=${project}`)
  await page.waitForLoadState('domcontentloaded')
  return resumes
}

test('a refused resume names the window and says the scan stays paused', async ({ page }) => {
  const resumes = await pausedGraph(page)
  await page.getByTitle('Resume Recon').click()
  await expect(page.getByText(TOAST)).toBeVisible()
  expect(resumes).toEqual(['POST'])
  await expect(page.getByTitle('Resume Recon')).toBeVisible()
})

test('narrow screen: the refusal is readable at 390 px', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const resumes = await pausedGraph(page)
  await page.getByTitle('Resume Recon').first().click()
  const toast = page.getByText(TOAST)
  await expect(toast).toBeVisible()
  expect(resumes).toEqual(['POST'])
  // The toast slides in from the right, so it is measured once it has settled.
  await expect.poll(async () => {
    const box = (await toast.boundingBox())!
    return box.x >= 0 && box.x + box.width <= 390
  }).toBe(true)
})
