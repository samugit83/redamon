import { test, expect, type Page, type APIRequestContext } from '@playwright/test'
import { existsSync, mkdirSync, readdirSync, rmSync, truncateSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { envValue, loginThroughUi } from './uiLogin'

/**
 * Agent Workspace: folder, archive and large-file upload through the real UI.
 *
 * Signs in ONCE through the login form with UI_LOGIN_USERNAME /
 * UI_LOGIN_PASSWORD from the repository .env (the owner's account: a failed
 * login is never retried, because the login route locks an account after
 * repeated failures), then reuses that session. Everything runs in a throwaway
 * project holding synthetic files only.
 *
 * The two zips in fixtures/workspace-import/ were made with:
 *   python3 -c "import zipfile
 *   with zipfile.ZipFile('sample-archive.zip','w') as z:
 *       [z.writestr('sample-archive/'+n, 'synthetic '+n+'\n') for n in ('one.txt','two.txt','three.txt')]
 *   with zipfile.ZipFile('traversal.zip','w') as z: z.writestr('../evil.txt','must never be written\n')"
 */

const USER = envValue('UI_LOGIN_USERNAME')
const PASSWORD = envValue('UI_LOGIN_PASSWORD')
const STATE_PATH = join(tmpdir(), `redamon-e2e-workspace-import-${process.pid}.json`)
const FIXTURES = join(__dirname, '..', 'fixtures', 'workspace-import')
const WORKSPACE_ON_HOST = join(__dirname, '..', '..', '..', 'agentic', 'agent-workspace')
const MIB = 1024 * 1024

// A trace records typed values, which would put the password in test-results/.
test.use({ trace: 'off', storageState: async ({}, use) => use(STATE_PATH) })
test.describe.configure({ mode: 'serial' })
test.skip(!USER || !PASSWORD, 'UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env')

let projectId = ''
let api: APIRequestContext

async function acceptOverlays(context: import('@playwright/test').BrowserContext) {
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
}

test.beforeAll(async ({ browser, baseURL }) => {
  const context = await browser.newContext({ storageState: undefined })
  await acceptOverlays(context)
  const page = await context.newPage()
  await loginThroughUi(page)
  await context.storageState({ path: STATE_PATH })
  api = context.request
  const res = await api.post('/api/projects', {
    data: { name: `e2e-workspace-import-${Date.now()}`, targetDomain: 'workspace-import.test' },
  })
  expect(res.ok(), await res.text()).toBeTruthy()
  projectId = (await res.json()).id
  expect(baseURL).toBeTruthy()
})

test.afterAll(async () => {
  if (projectId && api) {
    await api.post('/api/agent/workspace/reset', { data: { projectId } })
    await api.delete(`/api/projects/${projectId}`)
  }
  rmSync(STATE_PATH, { force: true })
})

test.beforeEach(async ({ context }) => {
  await acceptOverlays(context)
})

async function openDrawer(page: Page, folder = 'uploads') {
  await page.goto(`/graph?project=${projectId}`)
  await page.getByRole('button', { name: 'Toggle Workspace' }).click()
  const row = page.locator(`[data-name="${folder}"]`).first()
  await expect(row).toBeVisible({ timeout: 30_000 })
  const listed = page.waitForResponse(r => r.url().includes('/api/agent/workspace/list')
    && r.url().includes(`path=${encodeURIComponent(folder)}`))
  await row.click()
  await listed
}

function drawerBox(page: Page) {
  return page.getByRole('heading', { name: 'Agent Workspace' })
    .locator('xpath=ancestor::div[contains(@class,"drawerOpen")][1]').boundingBox()
}

async function pickFromMenu(page: Page, item: string, files: string | string[]) {
  const chooser = page.waitForEvent('filechooser')
  await page.getByRole('button', { name: 'Upload options' }).click()
  await page.getByRole('menuitem', { name: item }).click()
  await (await chooser).setFiles(files)
}

async function listing(path: string): Promise<{ name: string; isDir: boolean; size: number }[]> {
  const res = await api.get(`/api/agent/workspace/list?projectId=${projectId}&path=${encodeURIComponent(path)}`)
  expect(res.ok()).toBeTruthy()
  return (await res.json()).entries
}

function sampleFolder(root: string): string {
  const dir = join(root, 'sample-folder')
  mkdirSync(join(dir, 'a', 'b'), { recursive: true })
  writeFileSync(join(dir, 'a', 'b', 'c.txt'), 'nested synthetic file\n')
  writeFileSync(join(dir, 'empty.txt'), '')
  writeFileSync(join(dir, `${'é'.repeat(60)}-long-name.txt`), 'a name over 100 UTF-8 bytes\n')
  return dir
}

function bigFile(root: string, name: string, size: number): string {
  const p = join(root, name)
  writeFileSync(p, '')
  truncateSync(p, size)  // sparse: no 70 MiB of RAM, same bytes on the wire
  return p
}

function stagedSessions(): string[] {
  const staging = join(WORKSPACE_ON_HOST, '.staging', projectId)
  return existsSync(staging) ? readdirSync(staging).filter(n => n.startsWith('up-')) : []
}

const savedAs = (page: Page, path: string) =>
  page.getByRole('list', { name: 'Transfers' }).getByText(`Saved as ${path}`, { exact: false })

test('uploads a folder with its tree', async ({ page }, testInfo) => {
  await openDrawer(page)
  await pickFromMenu(page, 'Upload folder…', sampleFolder(testInfo.outputPath('src')))
  await expect(savedAs(page, 'uploads/sample-folder')).toBeVisible({ timeout: 60_000 })
  const top = await listing('uploads/sample-folder')
  expect(top.map(e => e.name).sort()).toEqual(['a', 'empty.txt', `${'é'.repeat(60)}-long-name.txt`].sort())
  expect((await listing('uploads/sample-folder/a/b')).map(e => e.name)).toEqual(['c.txt'])
  await page.locator('[data-name="sample-folder"]').first().click()
  await expect(page.locator(`[data-name="${'é'.repeat(60)}-long-name.txt"]`)).toBeVisible()
})

test('uploading the same folder again keeps both', async ({ page }, testInfo) => {
  await openDrawer(page)
  await pickFromMenu(page, 'Upload folder…', sampleFolder(testInfo.outputPath('src')))
  await expect(savedAs(page, 'uploads/sample-folder-2')).toBeVisible({ timeout: 60_000 })
})

test('uploads an archive and extracts it', async ({ page }) => {
  await openDrawer(page)
  await pickFromMenu(page, 'Upload archive and extract…', join(FIXTURES, 'sample-archive.zip'))
  await expect(savedAs(page, 'uploads/sample-archive')).toBeVisible({ timeout: 60_000 })
  expect((await listing('uploads/sample-archive')).map(e => e.name).sort()).toEqual(['one.txt', 'three.txt', 'two.txt'])
})

test('uploads a file larger than 60 MB', async ({ page }, testInfo) => {
  test.slow()
  await openDrawer(page)
  const file = bigFile(testInfo.outputPath(), 'big-70mib.bin', 70 * MIB)
  await pickFromMenu(page, 'Upload files…', file)
  await expect(savedAs(page, 'uploads/big-70mib.bin')).toBeVisible({ timeout: 120_000 })
  const row = (await listing('uploads')).find(e => e.name === 'big-70mib.bin')
  expect(row?.size).toBe(70 * MIB)
})

// Resolves once the server has made the upload's session. A staging poll must
// start after this: before it, an empty staging dir proves nothing.
function sessionCreated(page: Page) {
  return page.waitForResponse(r => r.request().method() === 'POST'
    && new URL(r.url()).pathname.endsWith('/api/agent/workspace/upload-sessions'))
}

async function delayChunks(page: Page, ms = 4000) {
  await page.route('**/api/agent/workspace/upload-sessions/*/chunk*', async route => {
    await new Promise(r => setTimeout(r, ms))
    await route.continue().catch(() => {})
  })
}

test('cancels an upload', async ({ page }, testInfo) => {
  await delayChunks(page)
  await openDrawer(page)
  const file = bigFile(testInfo.outputPath(), 'to-cancel.bin', 70 * MIB)
  const created = sessionCreated(page)
  await pickFromMenu(page, 'Upload files…', file)
  await page.getByRole('button', { name: 'Cancel to-cancel.bin' }).click()
  await created
  await expect(page.getByRole('list', { name: 'Transfers' }).getByText('Cancelled')).toBeVisible({ timeout: 30_000 })
  expect((await listing('uploads')).some(e => e.name.startsWith('to-cancel'))).toBe(false)
  // A cancel deletes the session, even one cancelled while it was being created.
  await expect.poll(stagedSessions, { timeout: 10_000 }).toEqual([])
})

test('a traversal archive is refused', async ({ page }) => {
  await openDrawer(page)
  await pickFromMenu(page, 'Upload archive and extract…', join(FIXTURES, 'traversal.zip'))
  const alert = page.getByRole('list', { name: 'Transfers' }).getByRole('alert')
  await expect(alert).toContainText('unsafe_path', { timeout: 60_000 })
  expect((await listing('uploads')).some(e => e.name === 'traversal' || e.name === 'evil.txt')).toBe(false)
})

test('the drawer works at its 320 px minimum width', async ({ page, context }, testInfo) => {
  await context.addInitScript(() => localStorage.setItem('redamon-filesystem-drawer-width', '320'))
  expect((await api.post('/api/agent/workspace/mkdir', { data: { projectId, path: 'uploads/narrow-row' } })).ok()).toBeTruthy()
  await delayChunks(page, 8000)
  await openDrawer(page)
  const viewport = page.viewportSize()!
  await page.getByRole('button', { name: 'Upload options' }).click()
  for (const name of ['Upload files…', 'Upload folder…', 'Upload archive and extract…']) {
    const box = (await page.getByRole('menuitem', { name }).boundingBox())!
    expect(box.x).toBeGreaterThanOrEqual(0)
    expect(box.x + box.width).toBeLessThanOrEqual(viewport.width)
  }
  await page.keyboard.press('Escape')

  const chooser = page.waitForEvent('filechooser')
  await page.getByTitle('Upload file(s) to current directory').click()
  const created = sessionCreated(page)
  await (await chooser).setFiles(bigFile(testInfo.outputPath(), 'narrow.bin', 40 * MIB))
  const cancel = page.getByRole('button', { name: 'Cancel narrow.bin' })
  await expect(cancel).toBeVisible()
  const drawer = (await drawerBox(page))!
  expect(drawer.width).toBeLessThanOrEqual(330)
  const row = page.locator('[data-name="narrow-row"]').first()
  await row.hover()
  const rowBox = (await row.boundingBox())!
  for (const button of await row.getByRole('button').all()) {
    const b = (await button.boundingBox())!
    expect(b.x).toBeGreaterThanOrEqual(rowBox.x - 1)
    expect(b.x + b.width).toBeLessThanOrEqual(rowBox.x + rowBox.width + 1)
    expect(b.x).toBeGreaterThanOrEqual(drawer.x - 1)
    expect(b.x + b.width).toBeLessThanOrEqual(drawer.x + drawer.width + 1)
  }
  await cancel.click()
  await expect(page.getByRole('list', { name: 'Transfers' }).getByText('Cancelled')).toBeVisible({ timeout: 30_000 })
  await created
  await expect.poll(stagedSessions, { timeout: 10_000 }).toEqual([])
})

test('leaving the graph page aborts an in-browser upload', async ({ page, context }, testInfo) => {
  // Slow the upload with network throttling, not page.route: with interception
  // on, Chromium drops a keepalive request the unloading page sends.
  const cdp = await context.newCDPSession(page)
  await cdp.send('Network.enable')
  await cdp.send('Network.emulateNetworkConditions', {
    offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: 256 * 1024,
  })
  await openDrawer(page)
  // Leave once bytes are on the wire: that is when the browser can still say
  // which session to delete (a create in flight at unload is left to the
  // server's idle sweep).
  const sending = page.waitForRequest(r => r.method() === 'PUT' && r.url().includes('/chunk'))
  await pickFromMenu(page, 'Upload files…', bigFile(testInfo.outputPath(), 'abandoned.bin', 70 * MIB))
  await sending
  page.once('dialog', d => d.accept())  // the browser's own leave-page prompt
  await page.goto('/projects')
  await page.goto(`/graph?project=${projectId}`)
  expect((await listing('uploads')).some(e => e.name.startsWith('abandoned'))).toBe(false)
  await expect.poll(stagedSessions, { timeout: 10_000 }).toEqual([])
  const jobs = await (await api.get(`/api/agent/workspace/jobs?projectId=${projectId}`)).json()
  expect((jobs.jobs || []).some((j: { tool_name: string }) => j.tool_name === 'workspace_upload'
    && j.args && (j.args as { name?: string }).name === 'abandoned.bin')).toBe(false)
})
