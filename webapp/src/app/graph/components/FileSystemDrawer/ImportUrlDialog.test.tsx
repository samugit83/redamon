/**
 * The "Import from URL" dialog: check, preview, import, and the GitHub token
 * help. The real useCredentialKeys and CredentialShortcut run against a fetch
 * mock of /api/users/<id>/settings; the effective user and the signed-in user
 * are mocked so a test can act as another user.
 *
 * Run: npx vitest run src/app/graph/components/FileSystemDrawer/ImportUrlDialog.test.tsx
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup, within } from '@testing-library/react'
import { IMPORT_PRESETS } from '@/lib/workspaceImport/presets'
import { ImportUrlDialog, type ImportJob } from './ImportUrlDialog'

const ids = vi.hoisted(() => ({ effective: 'u1' as string | null, signedIn: 'u1' }))
vi.mock('@/providers/ProjectProvider', () => ({
  useOptionalProject: () => ({ userId: ids.effective }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: ids.signedIn, name: 'Admin', email: 'a@example.test', role: 'admin' } }),
}))

// ---------------------------------------------------------------------------
// fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string; method: string; body?: Record<string, unknown> }

let calls: FetchCall[] = []
let tokenSet = false
let resolveAnswer: (body: Record<string, unknown>) => Response
let importAnswer: (body: Record<string, unknown>) => Response

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

const OWNER_REPO = 'https://github.com/example-owner/example-repo'

const GITHUB_REPO = {
  kind: 'github-repo', url: OWNER_REPO, suggestedName: 'example-repo', host: 'github.com',
  details: { ref: 'main', sha7: 'abc1234', files: 12, bytes: 2048, subpath: '', private: false },
  warnings: ['history_not_included', 'tree_truncated'], supported: true,
}

const GITLAB_REPO = {
  kind: 'gitlab-repo', url: 'https://gitlab.com/example-group/example-project', suggestedName: 'example-project',
  host: 'gitlab.com', details: { ref: 'main', private: false }, warnings: ['history_not_included'], supported: true,
}

function refusal(code: string, error: string, status: number, extra: Record<string, unknown> = {}): Response {
  return json({ error, code, upstreamStatus: status, ...extra }, status)
}

beforeEach(() => {
  calls = []
  tokenSet = false
  ids.effective = 'u1'
  ids.signedIn = 'u1'
  resolveAnswer = () => json(GITHUB_REPO)
  importAnswer = (body) => json({ jobId: 'a'.repeat(32), kind: 'github-repo', destDir: body.destDir, name: body.name ?? 'example-repo' }, 202)
  global.fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    const method = init?.method ?? 'GET'
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined
    calls.push({ url, method, body })
    if (url === '/api/users/u1/settings' && method === 'GET') {
      return json({ githubAccessToken: tokenSet ? '••••••••abcd' : '' })
    }
    if (url === '/api/users/u1/settings' && method === 'PUT') {
      tokenSet = true
      return json({ ok: true })
    }
    if (url === '/api/agent/workspace/import-url/resolve') return resolveAnswer(body)
    if (url === '/api/agent/workspace/import-url') return importAnswer(body)
    return json({ error: 'unexpected call', code: 'test_unexpected' }, 500)
  }) as unknown as typeof fetch
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderDialog(props: { defaultDestDir?: string } = {}) {
  const onClose = vi.fn()
  const onImportJob = vi.fn<(job: ImportJob) => void>()
  render(
    <ImportUrlDialog
      projectId="p1"
      defaultDestDir={props.defaultDestDir ?? 'uploads'}
      onClose={onClose}
      onImportJob={onImportJob}
    />,
  )
  return { onClose, onImportJob }
}

const resolveCalls = () => calls.filter((c) => c.url === '/api/agent/workspace/import-url/resolve')
const importCalls = () => calls.filter((c) => c.url === '/api/agent/workspace/import-url')
const settingsLoaded = () => waitFor(() => expect(calls.some((c) => c.url === '/api/users/u1/settings')).toBe(true))

async function checkUrl(url: string) {
  fireEvent.change(screen.getByLabelText('Link'), { target: { value: url } })
  fireEvent.click(screen.getByRole('button', { name: 'Check' }))
  await waitFor(() => expect(screen.queryByRole('status', { name: 'Checking the link' })).not.toBeInTheDocument())
}

const importButton = () => screen.getByRole('button', { name: 'Import' }) as HTMLButtonElement
const tokenEditor = () => screen.queryByLabelText('GitHub Secret Hunt Token')

const NO_TOKEN_NOTE = /No GitHub token: public repositories only, and GitHub allows this server 60 requests an hour/
const ACT_AS_NOTE = 'You are acting as another user, so GitHub imports run without a token: public repositories only.'

// ---------------------------------------------------------------------------

describe('ImportUrlDialog: check and preview', () => {
  test('check renders the preview details', async () => {
    renderDialog()
    fireEvent.change(screen.getByLabelText('Link'), { target: { value: `  ${OWNER_REPO}  ` } })
    fireEvent.keyDown(screen.getByLabelText('Link'), { key: 'Enter' })
    await screen.findByText('GitHub repository')

    expect(resolveCalls()).toHaveLength(1)
    // The URL decides the subfolder on the first check.
    expect(resolveCalls()[0].body).toEqual({ projectId: 'p1', url: OWNER_REPO })
    expect(screen.getByLabelText('Name')).toHaveValue('example-repo')
    const facts = screen.getByRole('group', { name: 'Preview' })
    expect(within(facts).getByText('github.com')).toBeInTheDocument()
    expect(within(facts).getByText('main')).toBeInTheDocument()
    expect(within(facts).getByText('abc1234')).toBeInTheDocument()
    expect(within(facts).getByText('12 files · 2.0K')).toBeInTheDocument()
    expect(screen.getByText('Only the files are imported, not the git history.')).toBeInTheDocument()
    expect(screen.getByText(/GitHub listed only part of this repository/)).toBeInTheDocument()
    expect(importButton().disabled).toBe(false)
  })

  test('errors render the coded message', async () => {
    resolveAnswer = () => refusal('blocked_address',
      'The link points at a private, internal or metadata address. Only public internet addresses can be imported.', 403)
    renderDialog()
    await checkUrl('http://198.51.100.1/a.zip')

    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('The link points at a private, internal or metadata address.')
    expect(alert).toHaveTextContent('blocked_address · HTTP 403')
    expect(importButton().disabled).toBe(true)
  })

  test('disabled state', async () => {
    resolveAnswer = () => refusal('import_disabled', 'URL import is turned off on this server.', 403)
    renderDialog()
    await checkUrl(OWNER_REPO)
    expect(screen.getByText('URL import is turned off on this server.')).toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'Preview' })).not.toBeInTheDocument()
    expect(importButton().disabled).toBe(true)

    // Turned off between the check and the import: the same state.
    resolveAnswer = () => json(GITLAB_REPO)
    importAnswer = () => refusal('import_disabled', 'URL import is turned off on this server.', 403)
    await checkUrl(GITLAB_REPO.url)
    fireEvent.click(importButton())
    expect(await screen.findByText('URL import is turned off on this server.')).toBeInTheDocument()
    expect(importButton().disabled).toBe(true)
  })

  test('websites and documentation sites preview but cannot be imported', async () => {
    resolveAnswer = () => json({
      kind: 'docs-site', url: 'https://docs.example.test/', suggestedName: 'docs.example.test', host: 'docs.example.test',
      details: { contentType: 'text/html' }, warnings: [], supported: false,
    })
    renderDialog()
    await checkUrl('https://docs.example.test/')
    expect(screen.getByText('Documentation site')).toBeInTheDocument()
    expect(screen.getByText('Websites and documentation sites can be previewed but not imported yet.')).toBeInTheDocument()
    expect(importButton().disabled).toBe(true)
  })

  test('subfolder field prefilled for a tree URL', async () => {
    const treeUrl = `${OWNER_REPO}/tree/main/Discovery/Web-Content`
    resolveAnswer = (body) => {
      const subpath = typeof body.subpath === 'string' ? body.subpath : 'Discovery/Web-Content'
      return json({ ...GITHUB_REPO, url: treeUrl, suggestedName: subpath.split('/').pop() || 'example-repo',
        details: { ...GITHUB_REPO.details, subpath } })
    }
    renderDialog()
    await checkUrl(treeUrl)
    const field = screen.getByLabelText('Subfolder')
    expect(field).toHaveValue('Discovery/Web-Content')
    expect(screen.getByLabelText('Name')).toHaveValue('Web-Content')

    // An edited subfolder must be previewed before it can be imported.
    fireEvent.change(field, { target: { value: '/Discovery/DNS/' } })
    expect(importButton().disabled).toBe(true)
    expect(screen.getByText(/Check again to preview this subfolder/)).toBeInTheDocument()
    fireEvent.keyDown(field, { key: 'Enter' })
    await waitFor(() => expect(resolveCalls()).toHaveLength(2))
    expect(resolveCalls()[1].body).toEqual({ projectId: 'p1', url: treeUrl, subpath: 'Discovery/DNS' })
    await waitFor(() => expect(importButton().disabled).toBe(false))
    expect(screen.getByLabelText('Name')).toHaveValue('DNS')

    fireEvent.click(importButton())
    await waitFor(() => expect(importCalls()).toHaveLength(1))
    expect(importCalls()[0].body!.options).toEqual({ subpath: 'Discovery/DNS' })
    expect(importCalls()[0].body!.name).toBe('DNS')
  })

  test('preset fills the URL and checks', async () => {
    renderDialog()
    const preset = IMPORT_PRESETS[0]
    const chips = screen.getByRole('group', { name: 'Quick import' })
    expect(within(chips).getAllByRole('button')).toHaveLength(IMPORT_PRESETS.length)
    fireEvent.click(within(chips).getByRole('button', { name: preset.label }))
    expect(screen.getByLabelText('Link')).toHaveValue(preset.url)
    await waitFor(() => expect(resolveCalls()).toHaveLength(1))
    expect(resolveCalls()[0].body).toEqual({ projectId: 'p1', url: preset.url })
  })
})

describe('ImportUrlDialog: import', () => {
  test('destination defaults to the current folder', async () => {
    renderDialog({ defaultDestDir: 'notes/wordlists' })
    expect(screen.getByLabelText('Destination folder')).toHaveValue('notes/wordlists')
    await checkUrl(OWNER_REPO)
    fireEvent.change(screen.getByLabelText('Destination folder'), { target: { value: '/workspace/uploads/' } })
    fireEvent.click(importButton())
    await waitFor(() => expect(importCalls()).toHaveLength(1))
    expect(importCalls()[0].body!.destDir).toBe('uploads')
  })

  test('keep both is the default', async () => {
    renderDialog()
    await checkUrl(OWNER_REPO)
    expect(screen.getByRole('radio', { name: 'Keep both' })).toBeChecked()
    expect(screen.queryByText(/Replace overwrites/)).not.toBeInTheDocument()
    fireEvent.click(importButton())
    await waitFor(() => expect(importCalls()).toHaveLength(1))
    expect(importCalls()[0].body!.onConflict).toBe('keep_both')
  })

  test('replace shows a warning line and is sent', async () => {
    renderDialog()
    await checkUrl(OWNER_REPO)
    fireEvent.click(screen.getByRole('radio', { name: 'Replace' }))
    expect(screen.getByText(/Replace overwrites/)).toBeInTheDocument()
    fireEvent.click(importButton())
    await waitFor(() => expect(importCalls()).toHaveLength(1))
    expect(importCalls()[0].body!.onConflict).toBe('replace')
  })

  test('import body carries no token', async () => {
    tokenSet = true
    const { onClose, onImportJob } = renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'my-copy' } })
    fireEvent.click(importButton())
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))

    const sent = importCalls()[0].body!
    expect(Object.keys(sent).sort()).toEqual(['destDir', 'name', 'onConflict', 'options', 'projectId', 'url'])
    expect(sent).toEqual({
      projectId: 'p1', url: OWNER_REPO, destDir: 'uploads', name: 'my-copy', onConflict: 'keep_both', options: { subpath: '' },
    })
    for (const c of [...resolveCalls(), ...importCalls()]) expect(JSON.stringify(c.body)).not.toMatch(/token/i)
    expect(onImportJob).toHaveBeenCalledWith({
      jobId: 'a'.repeat(32), kind: 'github-repo', destDir: 'uploads', name: 'my-copy', host: 'github.com',
    })
  })

  test('busy and too-many states', async () => {
    importAnswer = () => refusal('too_many_imports', 'This project already has 2 imports running. Wait for one to finish.', 429)
    const { onClose, onImportJob } = renderDialog()
    await checkUrl(OWNER_REPO)
    fireEvent.click(importButton())
    const tooMany = await screen.findByRole('alert')
    expect(tooMany).toHaveTextContent('This project already has 2 imports running.')
    expect(tooMany).toHaveTextContent('too_many_imports · HTTP 429')
    expect(onImportJob).not.toHaveBeenCalled()

    const running = 'b'.repeat(32)
    importAnswer = () => refusal('busy', 'A running import is replacing this folder. Retry when it finishes.', 409, { jobId: running })
    fireEvent.click(importButton())
    expect(await screen.findByText(/An identical import is already running/)).toHaveTextContent(running.slice(0, 8))
    expect(screen.getByText(/An identical import is already running/)).toHaveTextContent('Transfers panel')
    // The panel follows the running job; the dialog stays open.
    expect(onImportJob).toHaveBeenCalledWith(expect.objectContaining({ jobId: running, destDir: 'uploads', name: 'example-repo' }))
    expect(onClose).not.toHaveBeenCalled()
  })
})

describe('ImportUrlDialog: GitHub token help', () => {
  test('github preview without a token shows the note and the token editor', async () => {
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    expect(await screen.findByText(NO_TOKEN_NOTE)).toBeInTheDocument()
    expect(tokenEditor()).toBeInTheDocument()
    expect(screen.getByText('This is the token Global Settings lists as GitHub Secret Hunt Token.')).toBeInTheDocument()
    expect(screen.getByText('Optional')).toBeInTheDocument()
  })

  test('github preview with a token shows no note', async () => {
    tokenSet = true
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    await screen.findByText('GitHub repository')
    expect(screen.queryByText(NO_TOKEN_NOTE)).not.toBeInTheDocument()
    expect(tokenEditor()).not.toBeInTheDocument()
  })

  test('non-github preview never shows the token note', async () => {
    resolveAnswer = () => json(GITLAB_REPO)
    renderDialog()
    await settingsLoaded()
    await checkUrl(GITLAB_REPO.url)
    await screen.findByText('GitLab repository')
    expect(screen.queryByText(NO_TOKEN_NOTE)).not.toBeInTheDocument()
    expect(tokenEditor()).not.toBeInTheDocument()

    // A lookalike host is not GitHub either, and its errors offer no editor.
    resolveAnswer = () => refusal('not_found', 'Not found.', 404)
    await checkUrl('https://github.com.example.test/o/r')
    expect(screen.getByRole('alert')).toHaveTextContent('not_found')
    expect(screen.queryByText(/If this repository is private/)).not.toBeInTheDocument()
    expect(tokenEditor()).not.toBeInTheDocument()
  })

  test('under act-as the note says no token is sent and shows no editor', async () => {
    ids.effective = 'u2'
    renderDialog()
    await checkUrl(OWNER_REPO)
    expect(await screen.findByText(ACT_AS_NOTE)).toBeInTheDocument()
    expect(screen.queryByText(NO_TOKEN_NOTE)).not.toBeInTheDocument()
    expect(tokenEditor()).not.toBeInTheDocument()

    resolveAnswer = () => refusal('not_found', 'Not found.', 404)
    await checkUrl(`${OWNER_REPO}-private`)
    expect(screen.getByText(ACT_AS_NOTE)).toBeInTheDocument()
    expect(tokenEditor()).not.toBeInTheDocument()
  })

  test('not_found without a token offers the editor with the private-repository line', async () => {
    resolveAnswer = () => refusal('not_found', 'Not found.', 404)
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    expect(screen.getByRole('alert')).toHaveTextContent('Not found. (not_found · HTTP 404')
    expect(await screen.findByText('If this repository is private, add a GitHub token that can read it.')).toBeInTheDocument()
    expect(tokenEditor()).toBeInTheDocument()
  })

  test('not_found with a token names the scopes to check', async () => {
    tokenSet = true
    resolveAnswer = () => refusal('not_found', 'Not found.', 404)
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    const line = await screen.findByText(/If this repository is private, check that your GitHub token can read it/)
    expect(line).toHaveTextContent('a classic token needs the repo scope; a fine-grained one needs read access to Contents')
    expect(tokenEditor()).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Replace' })).toBeInTheDocument()
  })

  test('rate_limited without a token offers the editor; with a token it does not', async () => {
    resolveAnswer = () => refusal('rate_limited', "GitHub's hourly rate limit for this server is used up.", 429)
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    expect(await screen.findByText("GitHub's hourly limit for this server is used up. A token lifts it to 5,000 requests an hour."))
      .toBeInTheDocument()
    expect(tokenEditor()).toBeInTheDocument()
    cleanup()

    tokenSet = true
    calls = []
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    expect(await screen.findByText("Your token's hourly GitHub limit is used up. Try again later.")).toBeInTheDocument()
    expect(tokenEditor()).not.toBeInTheDocument()
  })

  test('auth_failed asks to replace the token', async () => {
    tokenSet = true
    resolveAnswer = () => refusal('auth_failed', 'GitHub refused the token: it may be expired or revoked.', 403)
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    expect(await screen.findByText('GitHub refused your token: it may be expired or revoked. Replace it.')).toBeInTheDocument()
    expect(tokenEditor()).toBeInTheDocument()
  })

  test('saving the token re-runs check', async () => {
    resolveAnswer = () => refusal('not_found', 'Not found.', 404)
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    await screen.findByText('If this repository is private, add a GitHub token that can read it.')

    resolveAnswer = () => json(GITHUB_REPO)
    fireEvent.change(tokenEditor()!, { target: { value: 'ghp_example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(resolveCalls()).toHaveLength(2))
    const put = calls.find((c) => c.method === 'PUT')
    expect(put?.body).toEqual({ githubAccessToken: 'ghp_example' })
    // The server reads the token itself; the browser's check still carries none.
    expect(resolveCalls()[1].body).toEqual({ projectId: 'p1', url: OWNER_REPO })
    await screen.findByText('GitHub repository')
    expect(screen.getByText(/Token saved to Global Settings/)).toBeInTheDocument()
    expect(tokenEditor()).not.toBeInTheDocument()
  })

  test('the token note never disables Import', async () => {
    renderDialog()
    await settingsLoaded()
    await checkUrl(OWNER_REPO)
    await screen.findByText(NO_TOKEN_NOTE)
    expect(importButton().disabled).toBe(false)
    fireEvent.click(importButton())
    await waitFor(() => expect(importCalls()).toHaveLength(1))
  })
})
