/**
 * Folder, archive and large-file uploads in the FileSystemDrawer: the upload
 * menu, drop traversal, folder-row drop targets, and the transfers panel.
 *
 * Harness as in FileSystemDrawer.test.tsx (mocked Drawer, mocked
 * useAlertModal, fetch mock). uploadBlob and waitForJob are replaced by
 * controllable fakes; the unmount test puts the real uploadBlob back so the
 * session DELETE it sends is the one asserted.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup, act, within } from '@testing-library/react'
import type * as UploadSessionModule from '@/lib/workspaceUpload/uploadSession'
import { ApiError } from '@/lib/apiError'
import { ARCHIVE_ACCEPT } from '@/lib/workspaceUpload/entries'
import { FileSystemDrawer } from './FileSystemDrawer'

vi.mock('@/components/ui/Drawer', () => ({
  Drawer: ({ isOpen, children, title }: { isOpen: boolean; children: React.ReactNode; title?: React.ReactNode }) => (
    <div data-testid="drawer" data-open={isOpen ? 'true' : 'false'}>
      {title && <div data-testid="drawer-title">{title}</div>}
      {children}
    </div>
  ),
}))

const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui', async (orig) => {
  const real = (await orig()) as Record<string, unknown>
  return { ...real, useAlertModal: () => alertSpies }
})

const uploadMocks = vi.hoisted(() => ({ uploadBlob: vi.fn(), waitForJob: vi.fn() }))
vi.mock('@/lib/workspaceUpload/uploadSession', async (orig) => {
  const real = (await orig()) as typeof UploadSessionModule
  return { ...real, uploadBlob: uploadMocks.uploadBlob, waitForJob: uploadMocks.waitForJob }
})

// ---------------------------------------------------------------------------
// fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string; init?: RequestInit }

let fetchCalls: FetchCall[] = []
let fetchHandler: (url: string, init?: RequestInit) => Promise<Response>

const sampleEntries = [
  { name: 'my-dir', path: 'my-dir', isDir: true, isSymlink: false, size: 0, mtime: '2026-05-14T10:00:00Z' },
  { name: 'linked', path: 'linked', isDir: true, isSymlink: true, size: 0, mtime: '2026-05-14T10:00:00Z' },
  { name: 'a.txt', path: 'a.txt', isDir: false, isSymlink: false, size: 42, mtime: '2026-05-14T10:01:00Z' },
]

function listAndOk(url: string): Response {
  if (url.includes('/api/agent/workspace/list')) return new Response(JSON.stringify({ entries: sampleEntries }), { status: 200 })
  return new Response(JSON.stringify({ ok: true }), { status: 200 })
}

// ---------------------------------------------------------------------------
// Controllable uploadBlob / waitForJob
// ---------------------------------------------------------------------------

interface PendingUpload {
  opts: UploadSessionModule.UploadBlobOptions
  resolve: (r: UploadSessionModule.UploadResult) => void
  reject: (e: unknown) => void
}
interface PendingJob {
  projectId: string
  jobId: string
  opts: UploadSessionModule.WaitForJobOptions
  resolve: (job: UploadSessionModule.WorkspaceJob) => void
}

let pendingUploads: PendingUpload[] = []
let pendingJobs: PendingJob[] = []

const JOB_ID = 'f'.repeat(32)

function job(status: UploadSessionModule.JobStatus, extra: Partial<UploadSessionModule.WorkspaceJob> = {}): UploadSessionModule.WorkspaceJob {
  return { job_id: JOB_ID, status, error: null, progress: null, tool_name: 'workspace_upload', ...extra }
}

beforeEach(() => {
  fetchCalls = []
  fetchHandler = async (url) => listAndOk(url)
  global.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const urlStr = typeof url === 'string' ? url : url.toString()
    fetchCalls.push({ url: urlStr, init })
    return fetchHandler(urlStr, init)
  }) as unknown as typeof fetch
  alertSpies.alertError.mockClear()
  alertSpies.alertWarning.mockClear()
  alertSpies.dangerConfirm.mockClear().mockResolvedValue(true)

  pendingUploads = []
  pendingJobs = []
  uploadMocks.uploadBlob.mockReset().mockImplementation((opts: UploadSessionModule.UploadBlobOptions) =>
    new Promise((resolve, reject) => {
      pendingUploads.push({ opts, resolve, reject })
      opts.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
    }))
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
  vi.useRealTimers()
})

// ---------------------------------------------------------------------------
// Pickers, files and drops
// ---------------------------------------------------------------------------

/** Collects the <input type="file"> elements the drawer creates, with the native picker suppressed. */
function captureInputs(): HTMLInputElement[] {
  const inputs: HTMLInputElement[] = []
  const origCreate = document.createElement.bind(document)
  vi.spyOn(document, 'createElement').mockImplementation(((tag: string, opts?: ElementCreationOptions) => {
    const el = origCreate(tag, opts)
    if (tag === 'input') {
      inputs.push(el as HTMLInputElement)
      ;(el as HTMLInputElement).click = vi.fn()
    }
    return el
  }) as typeof document.createElement)
  return inputs
}

function pick(input: HTMLInputElement, files: File[]) {
  Object.defineProperty(input, 'files', { value: files })
  act(() => { input.onchange?.(new Event('change')) })
}

const MIB = 1024 * 1024

function sized(name: string, size: number): File {
  const f = new File(['x'], name)
  Object.defineProperty(f, 'size', { value: size })
  return f
}

function inFolder(content: string, rel: string): File {
  const f = new File([content], rel.split('/').pop()!)
  Object.defineProperty(f, 'webkitRelativePath', { value: rel })
  return f
}

function fileEntry(name: string, content = name): FileSystemFileEntry {
  const file = new File([content], name)
  return { isFile: true, isDirectory: false, name, file: (ok: (f: File) => void) => ok(file) } as unknown as FileSystemFileEntry
}

function dirEntry(name: string, children: FileSystemEntry[]): FileSystemDirectoryEntry {
  return {
    isFile: false, isDirectory: true, name,
    createReader: () => {
      let done = false
      return { readEntries: (ok: (batch: FileSystemEntry[]) => void) => { ok(done ? [] : children); done = true } }
    },
  } as unknown as FileSystemDirectoryEntry
}

function dropData(entries: FileSystemEntry[]) {
  return {
    dataTransfer: {
      items: entries.map((entry) => ({ kind: 'file', webkitGetAsEntry: () => entry, getAsFile: () => null })),
      files: [],
      types: ['Files'],
    },
  }
}

function listCalls(): FetchCall[] {
  return fetchCalls.filter((c) => c.url.includes('/api/agent/workspace/list'))
}

function uploadRouteCalls(): FetchCall[] {
  return fetchCalls.filter((c) => c.url.includes('/api/agent/workspace/upload') && !c.url.includes('upload-sessions'))
}

async function renderDrawer(props: { projectId?: string; initialPath?: string } = {}) {
  const view = render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId={props.projectId ?? 'p1'} initialPath={props.initialPath} />)
  await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
  return view
}

function openMenu() {
  fireEvent.click(screen.getByRole('button', { name: 'Upload options' }))
  return screen.getByRole('menu')
}

async function startFolderDrop(name = 'site') {
  fireEvent.drop(document.querySelector('[class*="entryList"]')!, dropData([dirEntry(name, [fileEntry('index.html')])]))
  await waitFor(() => expect(pendingUploads).toHaveLength(1))
  return pendingUploads[0]
}

function transferRow(name: string): HTMLElement {
  const panel = screen.getByRole('list', { name: 'Transfers' })
  return within(panel).getByText(name).closest('li') as HTMLElement
}

// ---------------------------------------------------------------------------

describe('FileSystemDrawer: upload menu', () => {
  test('upload menu offers files, folder and archive', async () => {
    await renderDrawer()
    const trigger = screen.getByRole('button', { name: 'Upload options' })
    expect(trigger).toHaveAttribute('aria-haspopup', 'menu')
    // The plain Upload button keeps opening the file picker in one click.
    expect(screen.getByTitle('Upload file(s) to current directory')).toBeInTheDocument()

    const menu = openMenu()
    expect(within(menu).getAllByRole('menuitem').map((i) => i.textContent)).toEqual([
      'Upload files…', 'Upload folder…', 'Upload archive and extract…', 'Import from URL…',
    ])
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()

    // Keyboard: Enter opens it and focus lands on the first item.
    trigger.focus()
    fireEvent.keyDown(trigger, { key: 'Enter' })
    const items = within(screen.getByRole('menu')).getAllByRole('menuitem')
    await waitFor(() => expect(document.activeElement).toBe(items[0]))
  })

  test('folder pick starts a folder transfer to the current folder', async () => {
    const inputs = captureInputs()
    await renderDrawer({ initialPath: 'uploads' })
    fireEvent.click(within(openMenu()).getByText('Upload folder…'))
    const input = inputs[inputs.length - 1]
    expect(input.webkitdirectory).toBe(true)

    pick(input, [inFolder('<h1>', 'site/index.html'), inFolder('a{}', 'site/css/a.css')])

    await waitFor(() => expect(uploadMocks.uploadBlob).toHaveBeenCalledTimes(1))
    const opts = pendingUploads[0].opts
    expect(opts).toMatchObject({ projectId: 'p1', kind: 'folder', name: 'site', destDir: 'uploads', onConflict: 'keep_both' })
    expect(typeof opts.entries).toBe('number')
    expect(opts.entries).toBeGreaterThan(0)
    const tar = new TextDecoder().decode(await opts.blob.arrayBuffer())
    expect(tar).toContain('site/index.html')
    expect(tar).toContain('site/css/a.css')
    expect(within(transferRow('site')).getByText('Uploading')).toBeInTheDocument()
    expect(uploadRouteCalls()).toHaveLength(0)
  })

  test('archive pick starts an archive transfer named without the extension', async () => {
    const inputs = captureInputs()
    await renderDrawer({ initialPath: 'uploads' })
    fireEvent.click(within(openMenu()).getByText('Upload archive and extract…'))
    const input = inputs[inputs.length - 1]
    expect(input.accept).toBe(ARCHIVE_ACCEPT)

    const archive = new File(['PK'], 'site-backup.tar.gz')
    pick(input, [archive])

    await waitFor(() => expect(uploadMocks.uploadBlob).toHaveBeenCalledTimes(1))
    expect(pendingUploads[0].opts).toMatchObject({ kind: 'archive', name: 'site-backup', destDir: 'uploads' })
    expect(pendingUploads[0].opts.blob).toBe(archive)
    expect(uploadRouteCalls()).toHaveLength(0)
  })

  test('a file over 32 MiB uses a session, a small file uses the existing route', async () => {
    const inputs = captureInputs()
    await renderDrawer()
    fireEvent.click(screen.getByTitle('Upload file(s) to current directory'))

    const small = new File(['hello'], 'small.txt')
    const exact = sized('exact.bin', 32 * MIB)
    const big = sized('big.iso', 32 * MIB + 1)
    pick(inputs[inputs.length - 1], [small, exact, big])

    await waitFor(() => expect(uploadRouteCalls()).toHaveLength(2))
    expect(uploadRouteCalls().map((c) => ((c.init!.body as FormData).get('file') as File).name)).toEqual(['small.txt', 'exact.bin'])
    await waitFor(() => expect(uploadMocks.uploadBlob).toHaveBeenCalledTimes(1))
    expect(pendingUploads[0].opts).toMatchObject({ kind: 'file', name: 'big.iso', destDir: '.' })
    expect(pendingUploads[0].opts.blob).toBe(big)

    // "Upload files…" in the menu is the same picker.
    fireEvent.click(within(openMenu()).getByText('Upload files…'))
    expect(inputs[inputs.length - 1].multiple).toBe(true)
    expect(inputs[inputs.length - 1].webkitdirectory).toBeFalsy()
  })

  test('existing overwrite prompt for small files is unchanged', async () => {
    let attempts = 0
    fetchHandler = async (url) => {
      if (url.includes('/api/agent/workspace/upload')) {
        attempts++
        return attempts === 1
          ? new Response(JSON.stringify({ error: 'exists', code: 'exists' }), { status: 409 })
          : new Response(JSON.stringify({ path: 'a.txt' }), { status: 200 })
      }
      return listAndOk(url)
    }
    const inputs = captureInputs()
    await renderDrawer()
    fireEvent.click(within(openMenu()).getByText('Upload files…'))
    pick(inputs[inputs.length - 1], [new File(['v'], 'a.txt')])

    await screen.findByText('File already exists')
    fireEvent.click(screen.getByText('Overwrite'))
    await waitFor(() => expect(uploadRouteCalls()).toHaveLength(2))
    expect((uploadRouteCalls()[1].init!.body as FormData).get('overwrite')).toBe('true')
    expect(uploadMocks.uploadBlob).not.toHaveBeenCalled()
    expect(screen.queryByRole('list', { name: 'Transfers' })).not.toBeInTheDocument()
  })

  test('a small upload into a busy folder alerts with the job instead of offering to overwrite', async () => {
    fetchHandler = async (url) => {
      if (url.includes('/api/agent/workspace/upload')) {
        return new Response(JSON.stringify({
          error: 'A running import is replacing this folder. Retry when it finishes.', code: 'busy', jobId: 'd'.repeat(32),
        }), { status: 409 })
      }
      return listAndOk(url)
    }
    const inputs = captureInputs()
    await renderDrawer()
    fireEvent.click(screen.getByTitle('Upload file(s) to current directory'))
    pick(inputs[inputs.length - 1], [new File(['v'], 'a.txt')])
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalled())
    const [message, title] = alertSpies.alertError.mock.calls[0] as unknown as [string, string]
    expect(title).toBe('Upload failed')
    expect(message).toContain('Running job dddddddd')
    expect(screen.queryByText('File already exists')).not.toBeInTheDocument()
  })

  test('the small-upload hint is unchanged', async () => {
    let release: () => void = () => {}
    const answered = new Promise<void>((r) => { release = r })
    fetchHandler = async (url) => {
      if (url.includes('/api/agent/workspace/upload')) {
        await answered
        return new Response(JSON.stringify({ path: 'a.txt' }), { status: 200 })
      }
      return listAndOk(url)
    }
    const inputs = captureInputs()
    await renderDrawer()
    fireEvent.click(screen.getByTitle('Upload file(s) to current directory'))
    pick(inputs[inputs.length - 1], [new File(['v'], 'a.txt')])
    expect(await screen.findByText('Uploading 1 file…')).toBeInTheDocument()
    release()
    await waitFor(() => expect(screen.queryByText('Uploading 1 file…')).not.toBeInTheDocument())
    expect(screen.queryByRole('list', { name: 'Transfers' })).not.toBeInTheDocument()
  })
})

describe('FileSystemDrawer: drop', () => {
  test('dropping a directory starts a folder transfer', async () => {
    await renderDrawer({ initialPath: 'uploads' })
    const list = document.querySelector('[class*="entryList"]') as HTMLElement
    const site = dirEntry('site', [fileEntry('index.html'), dirEntry('empty', [])])

    fireEvent.drop(list, dropData([site, fileEntry('site.zip', 'PK')]))

    await waitFor(() => expect(uploadMocks.uploadBlob).toHaveBeenCalledTimes(1))
    expect(pendingUploads[0].opts).toMatchObject({ kind: 'folder', name: 'site', destDir: 'uploads' })
    const tar = new TextDecoder().decode(await pendingUploads[0].opts.blob.arrayBuffer())
    expect(tar).toContain('site/empty/')
    // A dropped archive is a file like any other: uploaded as is, not extracted.
    await waitFor(() => expect(uploadRouteCalls()).toHaveLength(1))
    const fd = uploadRouteCalls()[0].init!.body as FormData
    expect((fd.get('file') as File).name).toBe('site.zip')
    expect(fd.get('path')).toBe('uploads')
  })

  test('dropping on a folder row targets that folder', async () => {
    await renderDrawer()
    const row = document.querySelector('[data-name="my-dir"]') as HTMLElement

    fireEvent.dragOver(row, { dataTransfer: { types: ['Files'] } })
    expect(row.className).toMatch(/entryDropTarget/)
    expect(screen.getByText('Drop to upload to my-dir')).toBeInTheDocument()

    fireEvent.drop(row, dropData([dirEntry('site', [fileEntry('a.html')])]))
    await waitFor(() => expect(uploadMocks.uploadBlob).toHaveBeenCalledTimes(1))
    expect(pendingUploads[0].opts.destDir).toBe('my-dir')
    expect(row.className).not.toMatch(/entryDropTarget/)
    // Committed: it no longer holds one of the two sending slots.
    await act(async () => pendingUploads[0].resolve({ jobId: JOB_ID, uploadId: 'u'.repeat(32) }))

    // A symlinked folder and a file row are not targets: the drop lands in the current folder.
    const link = document.querySelector('[data-name="linked"]') as HTMLElement
    fireEvent.dragOver(link, { dataTransfer: { types: ['Files'] } })
    expect(link.className).not.toMatch(/entryDropTarget/)
    fireEvent.drop(link, dropData([dirEntry('other', [fileEntry('b.html')])]))
    fireEvent.drop(document.querySelector('[data-name="a.txt"]')!, dropData([dirEntry('third', [fileEntry('c.html')])]))
    await waitFor(() => expect(uploadMocks.uploadBlob).toHaveBeenCalledTimes(3))
    expect(pendingUploads.slice(1).map((u) => u.opts.destDir)).toEqual(['.', '.'])
  })
})

describe('FileSystemDrawer: transfers panel', () => {
  test('transfer shows progress then Saved as and refreshes the listing', async () => {
    await renderDrawer({ initialPath: 'uploads' })
    const upload = await startFolderDrop()

    act(() => upload.opts.onProgress?.({ sentBytes: 512, totalBytes: 2048 }))
    let row = transferRow('site')
    expect(within(row).getByText('Uploading')).toBeInTheDocument()
    expect(within(row).getByText('512B / 2.0K')).toBeInTheDocument()
    expect(within(row).getByRole('progressbar')).toHaveAttribute('aria-valuenow', '25')

    await act(async () => upload.resolve({ jobId: JOB_ID, uploadId: 'u'.repeat(32) }))
    await waitFor(() => expect(pendingJobs).toHaveLength(1))
    expect(pendingJobs[0]).toMatchObject({ projectId: 'p1', jobId: JOB_ID })
    act(() => pendingJobs[0].opts.onProgress?.(job('running', { progress: { phase: 'extracting', files: 3, bytes: 300, totalBytes: 900 } })))
    row = transferRow('site')
    expect(within(row).getByText('Extracting')).toBeInTheDocument()
    expect(within(row).getByText('3 files · 300B / 900B')).toBeInTheDocument()

    const listsBefore = listCalls().length
    await act(async () => pendingJobs[0].resolve(job('done', { progress: { phase: 'done', path: 'uploads/site-2' } })))
    const saved = await screen.findByRole('button', { name: /Saved as uploads\/site-2/ })
    await waitFor(() => expect(listCalls().length).toBeGreaterThan(listsBefore))

    fireEvent.click(saved)
    await waitFor(() => expect(listCalls().pop()!.url).toContain(`path=${encodeURIComponent('uploads/site-2')}`))
    // Finished rows stay until dismissed.
    fireEvent.click(within(transferRow('site')).getByTitle('Dismiss'))
    expect(screen.queryByRole('list', { name: 'Transfers' })).not.toBeInTheDocument()
  })

  test('cancel aborts the upload', async () => {
    await renderDrawer()
    const upload = await startFolderDrop()

    fireEvent.click(within(transferRow('site')).getByTitle('Cancel transfer'))
    expect(upload.opts.signal?.aborted).toBe(true)
    await waitFor(() => expect(within(transferRow('site')).getByText('Cancelled')).toBeInTheDocument())

    // Once committed, Cancel asks the server to cancel the job instead.
    fireEvent.drop(document.querySelector('[class*="entryList"]')!, dropData([dirEntry('later', [fileEntry('x')])]))
    await waitFor(() => expect(pendingUploads).toHaveLength(2))
    await act(async () => pendingUploads[1].resolve({ jobId: JOB_ID, uploadId: 'u'.repeat(32) }))
    await waitFor(() => expect(pendingJobs).toHaveLength(1))
    fireEvent.click(within(transferRow('later')).getByTitle('Cancel transfer'))
    await waitFor(() => expect(fetchCalls.some((c) =>
      c.url === `/api/agent/workspace/jobs/${JOB_ID}/cancel?projectId=p1` && c.init?.method === 'POST')).toBe(true))
    await act(async () => pendingJobs[0].resolve(job('cancelled')))
    await waitFor(() => expect(within(transferRow('later')).getByText('Cancelled')).toBeInTheDocument())
  })

  test('failed job shows the coded message', async () => {
    const { TransferCancelledError, SESSION_SWEPT_REASON } = await vi.importActual<typeof UploadSessionModule>(
      '@/lib/workspaceUpload/uploadSession')
    await renderDrawer()
    const upload = await startFolderDrop()
    await act(async () => upload.resolve({ jobId: JOB_ID, uploadId: 'u'.repeat(32) }))
    await waitFor(() => expect(pendingJobs).toHaveLength(1))
    await act(async () => pendingJobs[0].resolve(job('failed', { error: 'unsafe_path' })))

    expect(await within(transferRow('site')).findByText(
      'The archive holds a path that leaves its folder (unsafe_path)')).toBeInTheDocument()

    // A refused upload shows the API message with its code.
    fireEvent.drop(document.querySelector('[class*="entryList"]')!, dropData([dirEntry('huge', [fileEntry('x')])]))
    await waitFor(() => expect(pendingUploads).toHaveLength(2))
    await act(async () => pendingUploads[1].reject(new ApiError({
      reason: 'Not enough free disk space on the server for this operation.', status: 413, code: 'insufficient_storage',
    })))
    expect(await within(transferRow('huge')).findByText(/Not enough free disk space.*insufficient_storage · HTTP 413/))
      .toBeInTheDocument()

    // A session swept by a reset is a cancellation with its reason, not an error.
    fireEvent.drop(document.querySelector('[class*="entryList"]')!, dropData([dirEntry('swept', [fileEntry('x')])]))
    await waitFor(() => expect(pendingUploads).toHaveLength(3))
    await act(async () => pendingUploads[2].reject(new TransferCancelledError(SESSION_SWEPT_REASON)))
    expect(await within(transferRow('swept')).findByText(
      'Cancelled: the workspace was reset or the agent restarted')).toBeInTheDocument()
  })

  test('the panel shows a waiting message during 429 back-off', async () => {
    await renderDrawer()
    const upload = await startFolderDrop()

    act(() => upload.opts.onWaiting?.(true))
    expect(within(transferRow('site')).getByText('Waiting for the server…')).toBeInTheDocument()
    act(() => upload.opts.onWaiting?.(false))
    expect(within(transferRow('site')).getByText('Uploading')).toBeInTheDocument()

    await act(async () => upload.resolve({ jobId: JOB_ID, uploadId: 'u'.repeat(32) }))
    await waitFor(() => expect(pendingJobs).toHaveLength(1))
    act(() => pendingJobs[0].opts.onWaiting?.(true))
    expect(within(transferRow('site')).getByText('Waiting for the server…')).toBeInTheDocument()
  })
})

describe('FileSystemDrawer: transfers and the page lifecycle', () => {
  test('unmount aborts in-flight uploads and deletes their sessions with keepalive', async () => {
    const real = await vi.importActual<typeof UploadSessionModule>('@/lib/workspaceUpload/uploadSession')
    uploadMocks.uploadBlob.mockImplementation(real.uploadBlob)
    let sessions = 0
    fetchHandler = (url, init) => {
      if (url === '/api/agent/workspace/upload-sessions' && init?.method === 'POST') {
        sessions++
        const uploadId = String(sessions).repeat(32)
        return Promise.resolve(new Response(JSON.stringify({ uploadId, chunkSize: 8 * MIB, maxBytes: 1 << 30 }), { status: 201 }))
      }
      if (init?.method === 'PUT') {
        // The chunk is still on the wire when the user leaves.
        return new Promise((_, reject) => init.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError'))))
      }
      return Promise.resolve(listAndOk(url))
    }
    const inputs = captureInputs()
    const { unmount } = await renderDrawer()
    fireEvent.click(screen.getByTitle('Upload file(s) to current directory'))
    pick(inputs[inputs.length - 1], [sized('one.iso', 40 * MIB), sized('two.iso', 40 * MIB), sized('three.iso', 40 * MIB)])

    // At most two transfers send bytes at a time; the third waits its turn.
    await waitFor(() => expect(fetchCalls.filter((c) => c.init?.method === 'PUT')).toHaveLength(2))
    expect(sessions).toBe(2)
    expect(within(transferRow('three.iso')).getByText('Queued')).toBeInTheDocument()

    unmount()

    const deletes = fetchCalls.filter((c) => c.init?.method === 'DELETE')
    expect(deletes.map((c) => c.url).sort()).toEqual([
      `/api/agent/workspace/upload-sessions/${'1'.repeat(32)}?projectId=p1`,
      `/api/agent/workspace/upload-sessions/${'2'.repeat(32)}?projectId=p1`,
    ])
    expect(deletes.every((c) => c.init?.keepalive === true)).toBe(true)
    await new Promise((r) => setTimeout(r, 20))
    expect(sessions).toBe(2)
  })

  test('committed transfers are not cancelled on unmount', async () => {
    const { unmount } = await renderDrawer()
    const upload = await startFolderDrop()
    await act(async () => upload.resolve({ jobId: JOB_ID, uploadId: 'u'.repeat(32) }))
    await waitFor(() => expect(pendingJobs).toHaveLength(1))

    unmount()

    // Polling stops with the drawer; the job itself keeps running on the server.
    expect(pendingJobs[0].opts.signal?.aborted).toBe(true)
    expect(fetchCalls.some((c) => c.url.includes('/cancel'))).toBe(false)
    expect(fetchCalls.some((c) => c.init?.method === 'DELETE')).toBe(false)
  })

  test('beforeunload is registered only while bytes are uploading', async () => {
    const leavePrompted = () => {
      const ev = new Event('beforeunload', { cancelable: true })
      window.dispatchEvent(ev)
      return ev.defaultPrevented
    }
    await renderDrawer()
    expect(leavePrompted()).toBe(false)

    const upload = await startFolderDrop()
    expect(leavePrompted()).toBe(true)

    await act(async () => upload.resolve({ jobId: JOB_ID, uploadId: 'u'.repeat(32) }))
    await waitFor(() => expect(pendingJobs).toHaveLength(1))
    expect(leavePrompted()).toBe(false)
  })

  test("switching project hides the other project's transfers and shows them again on return", async () => {
    const { rerender } = await renderDrawer()
    const upload = await startFolderDrop()
    expect(transferRow('site')).toBeInTheDocument()

    rerender(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p2" />)
    await waitFor(() => expect(listCalls().pop()!.url).toContain('projectId=p2'))
    expect(screen.queryByRole('list', { name: 'Transfers' })).not.toBeInTheDocument()

    rerender(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    expect(within(transferRow('site')).getByText('Uploading')).toBeInTheDocument()
    expect(upload.opts.signal?.aborted).toBe(false)
    expect(upload.opts.projectId).toBe('p1')
  })
})
