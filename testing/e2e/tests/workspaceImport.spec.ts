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

// ---------------------------------------------------------------------------
// Import from a URL. octocat/Hello-World and github/gitignore are GitHub's own
// long-lived public samples, and example.com is reserved by RFC 2606 for
// documentation: none of them is target data.
// ---------------------------------------------------------------------------

const OFFLINE_CODES = ['network_error', 'dns_failed', 'timeout']
const HELLO = 'https://github.com/octocat/Hello-World'

async function reachable(url: string): Promise<string> {
  const res = await api.post('/api/agent/workspace/import-url/resolve', { data: { projectId, url } })
  if (res.ok()) return ''
  const code = ((await res.json().catch(() => ({}))) as { code?: string }).code || `status_${res.status()}`
  if (OFFLINE_CODES.includes(code)) return 'agent has no internet (M3)'
  if (code === 'rate_limited') return "GitHub's hourly rate limit for this server is used up"
  // The account's own saved token, which every GitHub request carries: replacing
  // it in Global Settings > API Keys lets these tests run.
  if (code === 'auth_failed') return "GitHub refuses the signed-in user's GitHub token (auth_failed)"
  return ''
}

async function openImport(page: Page) {
  await page.getByRole('button', { name: 'Upload options' }).click()
  await page.getByRole('menuitem', { name: 'Import from URL…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Import from URL' })
  await expect(dialog).toBeVisible()
  return dialog
}

async function checkLink(dialog: import('@playwright/test').Locator, url: string) {
  await dialog.getByLabel('Link').fill(url)
  await dialog.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(dialog.getByRole('status', { name: 'Checking the link' })).toBeHidden({ timeout: 45_000 })
}

async function importLink(page: Page, url: string,
  prepare?: (dialog: import('@playwright/test').Locator) => Promise<void>) {
  const dialog = await openImport(page)
  await checkLink(dialog, url)
  if (prepare) await prepare(dialog)
  await dialog.getByRole('button', { name: 'Import', exact: true }).click()
  await expect(dialog).toBeHidden({ timeout: 30_000 })
}

async function importJobs(): Promise<{ args?: { url?: string } }[]> {
  const res = await api.get(`/api/agent/workspace/jobs?projectId=${projectId}`)
  const jobs = ((await res.json()).jobs || []) as { tool_name: string; args?: { url?: string } }[]
  return jobs.filter(j => j.tool_name === 'workspace_import')
}

async function fetchedAt(path: string): Promise<string> {
  const res = await api.get(`/api/agent/workspace/properties?projectId=${projectId}&path=${encodeURIComponent(path)}`)
  return ((await res.json()).import?.fetchedAt as string) || ''
}

const savedExactly = (page: Page, path: string) =>
  page.getByRole('list', { name: 'Transfers' }).getByTitle(path, { exact: true })

async function resync(page: Page, name: string) {
  const row = page.locator(`[data-name="${name}"]`).first()
  await row.hover()
  await row.getByRole('button', { name: `Re-sync ${name}` }).click()
  const confirm = page.getByRole('dialog', { name: 'Re-sync imported folder?' })
  await confirm.getByRole('button', { name: 'Re-sync', exact: true }).click()
}

test.describe('import from a URL', () => {
  let offline = ''
  test.beforeAll(async () => { offline = await reachable(HELLO) })

  test('previews a public GitHub repository', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    const dialog = await openImport(page)
    await checkLink(dialog, HELLO)
    const preview = dialog.getByRole('group', { name: 'Preview' })
    await expect(preview.getByText('GitHub repository')).toBeVisible()
    await expect(preview.getByText('master', { exact: true })).toBeVisible()
    await expect(preview.getByText(/^[1-9][\d,]* files? · /)).toBeVisible()
  })

  test('imports a public GitHub repository', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    await importLink(page, HELLO)
    await expect(savedExactly(page, 'uploads/Hello-World')).toBeVisible({ timeout: 120_000 })
    await expect(page.locator('[data-name="Hello-World"]').first().getByTitle('Imported')).toBeVisible()
    expect((await listing('uploads/Hello-World')).map(e => e.name)).toEqual(expect.arrayContaining(['README', '.import.json']))
  })

  test('imports only a GitHub subfolder', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    await importLink(page, 'https://github.com/github/gitignore/tree/main/Global')
    await expect(savedExactly(page, 'uploads/Global')).toBeVisible({ timeout: 180_000 })
    const names = (await listing('uploads/Global')).map(e => e.name)
    expect(names).toContain('macOS.gitignore')
    expect(names).not.toContain('Python.gitignore')
  })

  test('imports a single file from a blob link', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    await importLink(page, `${HELLO}/blob/master/README`)
    await expect(savedExactly(page, 'uploads/README')).toBeVisible({ timeout: 60_000 })
    expect((await listing('uploads')).some(e => e.name === 'README' && !e.isDir)).toBe(true)
  })

  test('keeps both on a second import', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    await importLink(page, HELLO)
    await expect(savedExactly(page, 'uploads/Hello-World-2')).toBeVisible({ timeout: 120_000 })
  })

  test('re-syncs an imported folder', async ({ page }) => {
    test.skip(!!offline, offline)
    const before = await fetchedAt('uploads/Hello-World')
    expect(before).not.toBe('')
    await page.waitForTimeout(1100)  // fetchedAt has one-second resolution
    await openDrawer(page)
    await resync(page, 'Hello-World')
    await expect(savedExactly(page, 'uploads/Hello-World')).toBeVisible({ timeout: 120_000 })
    expect(Date.parse(await fetchedAt('uploads/Hello-World'))).toBeGreaterThan(Date.parse(before))
  })

  test('cancels a running import', async ({ page }) => {
    test.skip(!!offline, offline)
    test.slow()
    await openDrawer(page)
    const dialog = await openImport(page)
    await dialog.getByRole('button', { name: 'atomic-red-team' }).click()
    await expect(dialog.getByRole('status', { name: 'Checking the link' })).toBeHidden({ timeout: 45_000 })
    await dialog.getByRole('button', { name: 'Import', exact: true }).click()
    const cancel = page.getByRole('button', { name: 'Cancel atomic-red-team' })
    await cancel.click({ timeout: 30_000 })
    await expect(page.getByRole('list', { name: 'Transfers' }).getByText('Cancelled')).toBeVisible({ timeout: 60_000 })
    expect((await listing('uploads')).some(e => e.name.startsWith('atomic-red-team'))).toBe(false)
  })

  test('refuses private and metadata addresses', async ({ page }) => {
    const before = (await importJobs()).length
    await openDrawer(page)
    const dialog = await openImport(page)
    for (const url of ['http://169.254.169.254/latest/meta-data/', 'http://localhost:3000/']) {
      await checkLink(dialog, url)
      await expect(dialog.getByRole('alert')).toContainText('private, internal or metadata address')
      await expect(dialog.getByRole('button', { name: 'Import', exact: true })).toBeDisabled()
    }
    expect((await importJobs()).length).toBe(before)
  })

  test('refuses a URL with credentials', async ({ page }) => {
    await openDrawer(page)
    const dialog = await openImport(page)
    await checkLink(dialog, 'https://user:pass@example.com/a.zip')
    await expect(dialog.getByRole('alert')).toContainText('user name or password')
  })

  test('the import dialog and imported rows work at 320 px', async ({ page, context }) => {
    await context.addInitScript(() => localStorage.setItem('redamon-filesystem-drawer-width', '320'))
    await openDrawer(page)
    const viewport = page.viewportSize()!
    const dialog = await openImport(page)
    for (const control of [dialog.getByLabel('Link'), dialog.getByRole('button', { name: 'Check', exact: true }),
      dialog.getByRole('button', { name: 'Import', exact: true })]) {
      const box = (await control.boundingBox())!
      expect(box.x).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width)
    }
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
    test.skip(!!offline, offline)
    const drawer = (await drawerBox(page))!
    const row = page.locator('[data-name="Hello-World"]').first()
    await row.hover()
    for (const el of [row.getByTitle('Imported'), row.getByRole('button', { name: 'Re-sync Hello-World' })]) {
      const b = (await el.boundingBox())!
      expect(b.x).toBeGreaterThanOrEqual(drawer.x - 1)
      expect(b.x + b.width).toBeLessThanOrEqual(drawer.x + drawer.width + 1)
    }
  })
})

test.describe('mirror a website', () => {
  const SITE = 'https://example.com/'
  let offline = ''
  test.beforeAll(async () => { offline = await reachable(SITE) })

  test('mirrors a website as raw files', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    await importLink(page, SITE, async (dialog) => {
      await expect(dialog.getByRole('radio', { name: 'Raw files' })).toBeChecked()
    })
    await expect(savedExactly(page, 'uploads/example.com')).toBeVisible({ timeout: 120_000 })
    await expect(page.locator('[data-name="example.com"]').first().getByTitle('Imported')).toBeVisible()
    expect((await listing('uploads/example.com')).map(e => e.name).sort())
      .toEqual(expect.arrayContaining(['.import.json', '_manifest.jsonl', 'index.html']))
  })

  test('mirrors a website as a readable copy', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    await importLink(page, SITE, async (dialog) => {
      await dialog.getByRole('radio', { name: 'Readable copy' }).check()
    })
    await expect(savedExactly(page, 'uploads/example.com-2')).toBeVisible({ timeout: 120_000 })
    const names = (await listing('uploads/example.com-2')).map(e => e.name)
    expect(names).toContain('index.md')
    expect(names.some(n => n.endsWith('.html'))).toBe(false)
  })

  test('robots and external assets are off by default', async ({ page }) => {
    test.skip(!!offline, offline)
    await openDrawer(page)
    const dialog = await openImport(page)
    await checkLink(dialog, SITE)
    const options = dialog.getByRole('group', { name: 'Mirror options' })
    await expect(options.getByRole('checkbox', { name: 'Respect robots.txt' })).not.toBeChecked()
    await expect(options.getByRole('checkbox', { name: 'Also fetch assets from other hosts' })).not.toBeChecked()
  })

  test('re-syncs a mirrored site', async ({ page }) => {
    test.skip(!!offline, offline)
    const before = await fetchedAt('uploads/example.com')
    await page.waitForTimeout(1100)
    await openDrawer(page)
    await resync(page, 'example.com')
    await expect(savedExactly(page, 'uploads/example.com')).toBeVisible({ timeout: 120_000 })
    expect(Date.parse(await fetchedAt('uploads/example.com'))).toBeGreaterThan(Date.parse(before))
  })

  test('mirror options fit at 320 px', async ({ page, context }) => {
    test.skip(!!offline, offline)
    await context.addInitScript(() => localStorage.setItem('redamon-filesystem-drawer-width', '320'))
    await openDrawer(page)
    const viewport = page.viewportSize()!
    const dialog = await openImport(page)
    await checkLink(dialog, SITE)
    const options = dialog.getByRole('group', { name: 'Mirror options' })
    const controls = [
      options.getByRole('radio', { name: 'Raw files' }), options.getByRole('radio', { name: 'Readable copy' }),
      options.getByLabel('Max pages'), options.getByLabel('Max depth'),
      options.getByRole('checkbox', { name: 'Respect robots.txt' }), options.getByText(/RedAmon identifies itself/),
      dialog.getByRole('button', { name: 'Import', exact: true }),
    ]
    for (const control of controls) {
      await control.scrollIntoViewIfNeeded()
      const box = (await control.boundingBox())!
      expect(box.x).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width)
    }
    expect(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true)
  })
})
