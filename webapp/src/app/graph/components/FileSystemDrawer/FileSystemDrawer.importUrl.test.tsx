/**
 * URL imports in the FileSystemDrawer: the menu entry, the import transfer,
 * the imported badge and Re-sync, busy answers, and the API Keys link.
 *
 * Harness as in FileSystemDrawer.upload.test.tsx (mocked Drawer, mocked
 * useAlertModal, fetch mock, controllable waitForJob). The dialog's user
 * context is mocked; its own behaviour is ImportUrlDialog.test.tsx's.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup, act, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import type * as UploadSessionModule from '@/lib/workspaceUpload/uploadSession'
import { FileSystemDrawer } from './FileSystemDrawer'

vi.mock('@/components/ui/Drawer', () => ({
  Drawer: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) => (
    <div data-testid="drawer" data-open={isOpen ? 'true' : 'false'}>{children}</div>
  ),
}))

const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async (_message: ReactNode, _title?: string, _opts?: unknown) => true),
}))
vi.mock('@/components/ui', async (orig) => {
  const real = (await orig()) as Record<string, unknown>
  return { ...real, useAlertModal: () => alertSpies }
})

const uploadMocks = vi.hoisted(() => ({ waitForJob: vi.fn() }))
vi.mock('@/lib/workspaceUpload/uploadSession', async (orig) => {
  const real = (await orig()) as typeof UploadSessionModule
  return { ...real, waitForJob: uploadMocks.waitForJob }
})

vi.mock('@/providers/ProjectProvider', () => ({ useOptionalProject: () => ({ userId: 'u1' }) }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'u1', name: 'User', email: 'u@example.test', role: 'standard' } }),
}))

// ---------------------------------------------------------------------------
// fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string; init?: RequestInit }

let fetchCalls: FetchCall[] = []
let fetchHandler: (url: string, init?: RequestInit) => Promise<Response>

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

const entries = [
  { name: 'example-repo', path: 'uploads/example-repo', isDir: true, isSymlink: false, size: 0, mtime: '2026-05-14T10:00:00Z', imported: true },
  {
    name: 'pack', path: 'uploads/pack', isDir: true, isSymlink: false, size: 0, mtime: '2026-05-14T10:00:00Z',
    imported: true, importKind: 'archive', resyncable: false,
  },
  { name: 'plain-dir', path: 'uploads/plain-dir', isDir: true, isSymlink: false, size: 0, mtime: '2026-05-14T10:00:00Z', imported: false },
  { name: 'a.txt', path: 'uploads/a.txt', isDir: false, isSymlink: false, size: 42, mtime: '2026-05-14T10:01:00Z', imported: false },
]

let resolveAnswer: (body: Record<string, unknown>) => Response
let importAnswer: (body: Record<string, unknown>) => Response
let jobSeq = 0
const nextJobId = () => String(++jobSeq).padStart(32, '0')

function githubPreview(name: string) {
  return {
    kind: 'github-repo', url: `https://github.com/example-owner/${name}`, suggestedName: name, host: 'github.com',
    details: { ref: 'main', sha7: 'abc1234', files: 3, bytes: 300, subpath: '', private: false },
    warnings: ['history_not_included'], supported: true,
  }
}

function defaultHandler(url: string, init?: RequestInit): Response {
  const body = typeof init?.body === 'string' ? JSON.parse(init.body) : {}
  if (url.includes('/api/agent/workspace/list')) return json({ entries })
  if (url === '/api/users/u1/settings') return json({ githubAccessToken: '' })
  if (url === '/api/agent/workspace/import-url/resolve') return resolveAnswer(body)
  if (url === '/api/agent/workspace/import-url') return importAnswer(body)
  return json({ ok: true })
}

// ---------------------------------------------------------------------------
// Controllable waitForJob
// ---------------------------------------------------------------------------

interface PendingJob {
  projectId: string
  jobId: string
  opts: UploadSessionModule.WaitForJobOptions
  resolve: (job: UploadSessionModule.WorkspaceJob) => void
}
let pendingJobs: PendingJob[] = []

function job(jobId: string, status: UploadSessionModule.JobStatus, extra: Partial<UploadSessionModule.WorkspaceJob> = {}): UploadSessionModule.WorkspaceJob {
  return { job_id: jobId, status, error: null, progress: null, tool_name: 'workspace_import', ...extra }
}

beforeEach(() => {
  fetchCalls = []
  jobSeq = 0
  resolveAnswer = (body) => json(githubPreview(String(body.url).split('/').pop() || 'example-repo'))
  importAnswer = (body) => json({
    jobId: nextJobId(), kind: 'github-repo', destDir: body.destDir, name: body.name,
  }, 202)
  fetchHandler = async (url, init) => defaultHandler(url, init)
  global.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const urlStr = typeof url === 'string' ? url : url.toString()
    fetchCalls.push({ url: urlStr, init })
    return fetchHandler(urlStr, init)
  }) as unknown as typeof fetch
  alertSpies.alertError.mockClear()
  alertSpies.dangerConfirm.mockClear().mockResolvedValue(true)

  pendingJobs = []
  uploadMocks.waitForJob.mockReset().mockImplementation(
    (projectId: string, jobId: string, opts: UploadSessionModule.WaitForJobOptions) =>
      new Promise((resolve, reject) => {
        pendingJobs.push({ projectId, jobId, opts, resolve })
        opts.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
      }))
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function renderDrawer() {
  const view = render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" initialPath="uploads" />)
  await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
  return view
}

function openImportDialog(): HTMLElement {
  fireEvent.click(screen.getByRole('button', { name: 'Upload options' }))
  fireEvent.click(within(screen.getByRole('menu')).getByText('Import from URL…'))
  return screen.getByRole('dialog', { name: 'Import from URL' })
}

/** Checks a link in the dialog and imports it; resolves once the transfer row is there. */
async function importLink(link: string): Promise<PendingJob> {
  const before = pendingJobs.length
  const dialog = openImportDialog()
  fireEvent.change(within(dialog).getByLabelText('Link'), { target: { value: link } })
  fireEvent.click(within(dialog).getByRole('button', { name: 'Check' }))
  const importBtn = within(dialog).getByRole('button', { name: 'Import' })
  await waitFor(() => expect(importBtn).not.toBeDisabled())
  fireEvent.click(importBtn)
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Import from URL' })).not.toBeInTheDocument())
  await waitFor(() => expect(pendingJobs.length).toBe(before + 1))
  return pendingJobs[pendingJobs.length - 1]
}

function transferRow(name: string): HTMLElement {
  const panel = screen.getByRole('list', { name: 'Transfers' })
  return within(panel).getByText(name).closest('li') as HTMLElement
}

function row(name: string): HTMLElement {
  return document.querySelector(`[data-name="${name}"]`) as HTMLElement
}

const callsTo = (path: string) => fetchCalls.filter((c) => c.url === path)

// ---------------------------------------------------------------------------

describe('FileSystemDrawer: import from URL', () => {
  test('menu opens the dialog', async () => {
    await renderDrawer()
    expect(screen.queryByRole('dialog', { name: 'Import from URL' })).not.toBeInTheDocument()
    const dialog = openImportDialog()
    // The destination starts at the folder the drawer shows.
    expect(within(dialog).getByLabelText('Destination folder')).toHaveValue('uploads')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog', { name: 'Import from URL' })).not.toBeInTheDocument()
    expect(callsTo('/api/agent/workspace/import-url')).toHaveLength(0)
  })

  test('import transfer follows job progress to Saved as', async () => {
    await renderDrawer()
    const pending = await importLink('https://github.com/example-owner/example-repo')
    expect(pending).toMatchObject({ projectId: 'p1', jobId: '1'.padStart(32, '0') })
    expect(JSON.parse(callsTo('/api/agent/workspace/import-url')[0].init!.body as string)).toMatchObject({
      projectId: 'p1', url: 'https://github.com/example-owner/example-repo', destDir: 'uploads', name: 'example-repo',
    })

    let item = transferRow('example-repo')
    expect(within(item).getByText('Starting')).toBeInTheDocument()
    act(() => pending.opts.onProgress?.(job(pending.jobId, 'running', { progress: { phase: 'resolving' } })))
    expect(within(transferRow('example-repo')).getByText('Resolving')).toBeInTheDocument()
    act(() => pending.opts.onProgress?.(job(pending.jobId, 'running', { progress: { phase: 'downloading', bytes: 300, totalBytes: 900 } })))
    item = transferRow('example-repo')
    expect(within(item).getByText('Downloading')).toBeInTheDocument()
    expect(within(item).getByText('300B / 900B')).toBeInTheDocument()
    act(() => pending.opts.onProgress?.(job(pending.jobId, 'running', { progress: { phase: 'extracting', files: 3 } })))
    expect(within(transferRow('example-repo')).getByText('Extracting')).toBeInTheDocument()
    act(() => pending.opts.onProgress?.(job(pending.jobId, 'running', { progress: { phase: 'placing' } })))
    expect(within(transferRow('example-repo')).getByText('Placing')).toBeInTheDocument()

    const listsBefore = fetchCalls.filter((c) => c.url.includes('/workspace/list')).length
    await act(async () => pending.resolve(job(pending.jobId, 'done', { progress: { phase: 'done', path: 'uploads/example-repo-2' } })))
    const saved = await screen.findByRole('button', { name: /Saved as uploads\/example-repo-2/ })
    await waitFor(() => expect(fetchCalls.filter((c) => c.url.includes('/workspace/list')).length).toBeGreaterThan(listsBefore))

    // A repository import saved a folder: "Saved as" opens it.
    fireEvent.click(saved)
    await waitFor(() => expect(fetchCalls.filter((c) => c.url.includes('/workspace/list')).pop()!.url)
      .toContain(`path=${encodeURIComponent('uploads/example-repo-2')}`))
  })

  test('a website copy that stopped at the page limit says so once done', async () => {
    resolveAnswer = () => json({
      kind: 'website', url: 'https://www.example.test/', suggestedName: 'www.example.test', host: 'www.example.test',
      details: {
        scopeHost: 'www.example.test', scopePath: '/',
        defaults: { outputMode: 'raw', maxPages: 300, maxDepth: 3, respectRobots: false, englishOnly: false, externalAssets: false },
      },
      warnings: [], supported: true,
    })
    importAnswer = (body) => json({ jobId: nextJobId(), kind: 'website', destDir: body.destDir, name: body.name }, 202)
    await renderDrawer()
    const pending = await importLink('https://www.example.test/')
    act(() => pending.opts.onProgress?.(job(pending.jobId, 'running', { progress: { phase: 'crawling', pages: 299, assets: 4 } })))
    expect(within(transferRow('www.example.test')).queryByText('Stopped at the page limit')).not.toBeInTheDocument()
    await act(async () => pending.resolve(job(pending.jobId, 'done', {
      progress: { phase: 'done', path: 'uploads/www.example.test', pages: 300, assets: 4, stoppedBecause: 'max_pages' },
    })))
    await screen.findByRole('button', { name: /Saved as uploads\/www\.example\.test/ })
    expect(within(transferRow('www.example.test')).getByText('Stopped at the page limit')).toBeInTheDocument()
  })

  test('cancelling an import cancels the job', async () => {
    await renderDrawer()
    const pending = await importLink('https://github.com/example-owner/example-repo')
    fireEvent.click(within(transferRow('example-repo')).getByTitle('Cancel transfer'))
    await waitFor(() => expect(fetchCalls.some((c) =>
      c.url === `/api/agent/workspace/jobs/${pending.jobId}/cancel?projectId=p1` && c.init?.method === 'POST')).toBe(true))
    await act(async () => pending.resolve(job(pending.jobId, 'cancelled')))
    await waitFor(() => expect(within(transferRow('example-repo')).getByText('Cancelled')).toBeInTheDocument())
  })
})

describe('FileSystemDrawer: imported folders', () => {
  test('imported rows show the badge', async () => {
    await renderDrawer()
    const imported = row('example-repo')
    expect(imported.className).toMatch(/entryImported/)
    expect(within(imported).getByTitle('Imported')).toBeInTheDocument()
    expect(within(imported).getByRole('button', { name: 'Re-sync example-repo' })).toBeInTheDocument()
    for (const name of ['plain-dir', 'a.txt']) {
      expect(within(row(name)).queryByTitle('Imported')).not.toBeInTheDocument()
      expect(within(row(name)).queryByRole('button', { name: /^Re-sync/ })).not.toBeInTheDocument()
    }
  })

  test('the badge names the kind, and an import that cannot be re-synced has no Re-sync', async () => {
    await renderDrawer()
    const icon = (name: string) => within(row(name)).getByTitle('Imported').querySelector('svg')?.getAttribute('class')
    expect(icon('example-repo')).toMatch(/lucide-git-branch/)
    expect(icon('pack')).toMatch(/lucide-globe/)
    expect(within(row('pack')).queryByRole('button', { name: /^Re-sync/ })).not.toBeInTheDocument()
  })

  test('re-sync asks for confirmation then posts', async () => {
    fetchHandler = async (url, init) => url === '/api/agent/workspace/import-url/resync'
      ? json({ jobId: 'c'.repeat(32), kind: 'github-repo', destDir: 'uploads', name: 'example-repo' }, 202)
      : defaultHandler(url, init)
    await renderDrawer()

    alertSpies.dangerConfirm.mockResolvedValueOnce(false)
    fireEvent.click(screen.getByRole('button', { name: 'Re-sync example-repo' }))
    await waitFor(() => expect(alertSpies.dangerConfirm).toHaveBeenCalledTimes(1))
    await new Promise((r) => setTimeout(r, 20))
    expect(callsTo('/api/agent/workspace/import-url/resync')).toHaveLength(0)

    fireEvent.click(screen.getByRole('button', { name: 'Re-sync example-repo' }))
    await waitFor(() => expect(callsTo('/api/agent/workspace/import-url/resync')).toHaveLength(1))
    const call = callsTo('/api/agent/workspace/import-url/resync')[0]
    expect(call.init?.method).toBe('POST')
    expect(JSON.parse(call.init!.body as string)).toEqual({ projectId: 'p1', path: 'uploads/example-repo' })
    await waitFor(() => expect(pendingJobs).toHaveLength(1))
    expect(pendingJobs[0].jobId).toBe('c'.repeat(32))
    expect(within(transferRow('example-repo')).getByText('Starting')).toBeInTheDocument()
  })

  test('re-sync confirmation names the kali-shell limitation', async () => {
    await renderDrawer()
    alertSpies.dangerConfirm.mockResolvedValueOnce(false)
    fireEvent.click(screen.getByRole('button', { name: 'Re-sync example-repo' }))
    await waitFor(() => expect(alertSpies.dangerConfirm).toHaveBeenCalledTimes(1))
    const [message, title] = alertSpies.dangerConfirm.mock.calls[0]
    const { container } = render(<>{message}</>)
    expect(container.textContent).toBe(
      'Re-sync replaces the contents of example-repo with a fresh copy from its source. Changes made inside it are lost, '
      + 'including files written by kali shell commands while it runs; the drawer and the agent\'s file tools are '
      + 'blocked until it finishes.')
    expect(container.querySelector('code')?.textContent).toBe('example-repo')
    expect(title).toMatch(/Re-sync/)
  })

  test('busy rename or delete shows the job message', async () => {
    const running = 'd'.repeat(32)
    const busy = () => json({
      error: 'A running import is replacing this folder. Retry when it finishes.', code: 'busy', upstreamStatus: 409, jobId: running,
    }, 409)
    fetchHandler = async (url, init) => url.includes('/workspace/rename') || init?.method === 'DELETE'
      ? busy()
      : defaultHandler(url, init)
    await renderDrawer()

    fireEvent.click(within(row('example-repo')).getByTitle('Rename'))
    const input = await screen.findByDisplayValue('example-repo')
    fireEvent.change(input, { target: { value: 'renamed' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledTimes(1))
    const [renameText, renameTitle] = alertSpies.alertError.mock.calls[0] as unknown as [string, string]
    expect(renameTitle).toBe('Rename failed')
    expect(renameText).toContain('A running import is replacing this folder. Retry when it finishes.')
    expect(renameText).toContain('busy · HTTP 409')
    expect(renameText).toContain(running.slice(0, 8))

    fireEvent.click(within(row('example-repo')).getByTitle('Delete'))
    await screen.findByText('Delete folder?')
    const modalButtons = screen.getAllByRole('button', { name: 'Delete' })
    fireEvent.click(modalButtons[modalButtons.length - 1])
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledTimes(2))
    const [deleteText, deleteTitle] = alertSpies.alertError.mock.calls[1] as unknown as [string, string]
    expect(deleteTitle).toBe('Delete failed')
    expect(deleteText).toContain('A running import is replacing this folder.')
    expect(deleteText).toContain(running.slice(0, 8))
  })

  test('properties show the import facts', async () => {
    fetchHandler = async (url, init) => url.includes('/workspace/properties')
      ? json({
        path: 'uploads/example-repo', type: 'dir', size: 0, mtime: '2026-05-14T10:00:00Z', mode: '0755',
        import: {
          kind: 'github-repo', host: 'github.com', sourcePath: '/example-owner/example-repo', ref: 'main',
          commit7: 'abc1234', fetchedAt: '2026-05-14T10:00:00Z', resyncable: true,
        },
      })
      : defaultHandler(url, init)
    await renderDrawer()
    fireEvent.click(within(row('example-repo')).getByTitle('Properties (size, hash, modified)'))
    await screen.findByText('github.com/example-owner/example-repo')
    expect(screen.getByText('GitHub repository')).toBeInTheDocument()
    expect(screen.getByText('abc1234')).toBeInTheDocument()
  })
})

describe('FileSystemDrawer: GitHub failures link to API Keys', () => {
  test('a github import failing with not_found, rate_limited or auth_failed links to API Keys', async () => {
    await renderDrawer()
    const outcomes: Array<[string, string]> = [
      ['repo-private', 'not_found'], ['repo-limited', 'rate_limited'], ['repo-refused', 'auth_failed'], ['repo-slow', 'timeout'],
    ]
    for (const [name, code] of outcomes) {
      const pending = await importLink(`https://github.com/example-owner/${name}`)
      await act(async () => pending.resolve(job(pending.jobId, 'failed', { error: code })))
      await within(transferRow(name)).findByRole('alert')
    }
    for (const [name] of outcomes.slice(0, 3)) {
      const link = within(transferRow(name)).getByRole('link', { name: 'Open API Keys' })
      expect(link).toHaveAttribute('href', '/settings?tab=keys')
      expect(link).toHaveAttribute('target', '_blank')
    }
    expect(within(transferRow('repo-private')).getByRole('alert')).toHaveTextContent('(not_found)')
    // A failure a token cannot fix gets no link.
    expect(within(transferRow('repo-slow')).queryByRole('link')).not.toBeInTheDocument()

    // Nor does another forge: this version sends it no token.
    resolveAnswer = () => json({
      kind: 'gitlab-repo', url: 'https://gitlab.com/example-group/gl-private', suggestedName: 'gl-private', host: 'gitlab.com',
      details: { ref: 'main', private: false }, warnings: [], supported: true,
    })
    importAnswer = (body) => json({ jobId: nextJobId(), kind: 'gitlab-repo', destDir: body.destDir, name: body.name }, 202)
    const gitlab = await importLink('https://gitlab.com/example-group/gl-private')
    await act(async () => gitlab.resolve(job(gitlab.jobId, 'failed', { error: 'not_found' })))
    await within(transferRow('gl-private')).findByRole('alert')
    expect(within(transferRow('gl-private')).queryByRole('link')).not.toBeInTheDocument()
  })

  test('a github re-sync failing with rate_limited links to API Keys', async () => {
    fetchHandler = async (url, init) => url === '/api/agent/workspace/import-url/resync'
      ? json({ jobId: 'e'.repeat(32), kind: 'github-repo', destDir: 'uploads', name: 'example-repo' }, 202)
      : defaultHandler(url, init)
    await renderDrawer()
    fireEvent.click(screen.getByRole('button', { name: 'Re-sync example-repo' }))
    await waitFor(() => expect(pendingJobs).toHaveLength(1))
    await act(async () => pendingJobs[0].resolve(job(pendingJobs[0].jobId, 'failed', { error: 'rate_limited' })))
    expect(await within(transferRow('example-repo')).findByRole('link', { name: 'Open API Keys' })).toBeInTheDocument()
  })
})
