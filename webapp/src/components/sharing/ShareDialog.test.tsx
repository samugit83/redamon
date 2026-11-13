/**
 * The share dialog (step 4.12; UI-07, SH-05, SH-20, SH-29, HD-22, ID-31; E2E P4-01, P4-02, P4-04):
 * an owner shares a project at Read by exact email with a preset (Viewer, Analyst, Custom with the
 * Raw data toggle), an optional end date and a note, sees the person the server bound as an
 * IdentityLabel, and lists, changes and revokes the shares. The Read + Write presets are offered
 * disabled. States: loading, empty, error, denied, sharing unavailable, rate-limited, acting as the
 * owner. The routes are 4.4's (fetch is the double); revoke's confirmation is the real AlertProvider.
 *
 * Run: npx vitest run --no-file-parallelism src/components/sharing/ShareDialog.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  user: null as null | Record<string, unknown>,
  fetch: vi.fn(),
}))
vi.mock('@/providers/AuthProvider', () => ({ useOptionalAuth: () => (h.user ? { user: h.user } : null) }))

import { ShareDialog } from './ShareDialog'
import { endOfDayIso } from './sharePresets'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const ALICE = { id: 'alice', name: 'Alice Owner', email: 'alice@example.test', accountType: 'member' }
const share = (over: Record<string, unknown> = {}) => ({
  user: { id: 'bob', name: 'Bob Reader', email: 'bob@example.test', status: 'active', accountType: 'member' },
  access: 'read', rawData: false, expiresAt: null, expired: false, note: null, grantedById: 'alice',
  grantedBy: ALICE, createdAt: '2026-11-13T10:00:00.000Z', updatedAt: '2026-11-13T10:00:00.000Z', ...over,
})

let listAnswers: Array<() => Response | Promise<Response>>
let grantAnswer: () => Response
let socketsClosed: boolean
const calls = (method: string) => h.fetch.mock.calls.filter(([, init]) => ((init as RequestInit | undefined)?.method ?? 'GET') === method)
const lastBody = (method: string) => JSON.parse(String((calls(method).at(-1)![1] as RequestInit).body))

function renderDialog(onClose = vi.fn()) {
  render(<AlertProvider><ShareDialog project={{ id: 'P1', name: 'Alpha recon' }} onClose={onClose} /></AlertProvider>)
  return onClose
}
const dialog = () => within(screen.getByRole('dialog', { name: 'Share "Alpha recon"' }))
const fillEmail = (value: string) => fireEvent.change(dialog().getByLabelText('Email'), { target: { value } })
const submit = () => fireEvent.click(dialog().getByRole('button', { name: 'Share' }))

beforeEach(() => {
  h.user = {
    id: 'alice', name: 'Alice Owner', email: 'alice@example.test', role: 'standard',
    flags: { identity: true, permissions: true, sharing: true, sharingWrite: false, governance: false },
    sharing: { enabled: true, maxLevel: 'read' },
  }
  listAnswers = []
  grantAnswer = () => json({ collaborator: share() }, 201)
  socketsClosed = true
  h.fetch.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (method === 'GET' && url === '/api/projects/P1/collaborators') {
      const next = listAnswers.shift()
      return next ? next() : json({ collaborators: [] })
    }
    if (method === 'POST' && url === '/api/projects/P1/collaborators') return grantAnswer()
    if (method === 'DELETE' && url === '/api/projects/P1/collaborators/bob') return json({ revoked: { projectId: 'P1', userId: 'bob' }, socketsClosed })
    if (method === 'PATCH' && url === '/api/projects/P1/collaborators/bob') return json({ collaborator: share({ rawData: true }) })
    return json({ error: 'unexpected' }, 500)
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('states', () => {
  test('loading, then empty', async () => {
    let release: (r: Response) => void = () => {}
    listAnswers.push(() => new Promise<Response>((r) => { release = r }))
    renderDialog()
    expect(dialog().getByRole('status')).toHaveTextContent('Loading who has access')
    release(json({ collaborators: [] }))
    expect(await dialog().findByText('Not shared with anyone yet.')).toBeInTheDocument()
  })

  test('error: the cause and its code, and Retry asks again', async () => {
    listAnswers.push(() => json({ error: "Could not list the project's shares", code: 'P1001' }, 500))
    listAnswers.push(() => json({ collaborators: [share()] }))
    renderDialog()
    const alert = await dialog().findByRole('alert')
    expect(alert).toHaveTextContent("Could not list the project's shares (P1001 · HTTP 500)")
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }))
    expect(await dialog().findByRole('group', { name: 'Bob Reader, bob@example.test, Member' })).toBeInTheDocument()
  })

  test('denied: the permission notice, and no share form', async () => {
    listAnswers.push(() => json({ error: 'Forbidden', code: 'forbidden', permission: 'project:share' }, 403))
    renderDialog()
    expect(await dialog().findByText('You do not have the permission this needs.')).toBeInTheDocument()
    expect(dialog().getByText('project:share')).toBeInTheDocument()
    expect(dialog().queryByLabelText('Email')).toBeNull()
    expect(dialog().queryByRole('button', { name: 'Share' })).toBeNull()
  })

  test('sharing not available (the routes answer 404): said, no form', async () => {
    listAnswers.push(() => json({ error: 'Not found' }, 404))
    renderDialog()
    expect(await dialog().findByText(/Sharing is not available for this project now/)).toBeInTheDocument()
    expect(dialog().queryByLabelText('Email')).toBeNull()
  })

  test('rate-limited: the lookup ceiling is said with its code; the form stays', async () => {
    grantAnswer = () => json({ error: 'Too many people looked up. Try again in a minute.', code: 'rate_limited', retryAfterSeconds: 42 }, 429)
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    fillEmail('bob@example.test')
    submit()
    expect(await dialog().findByRole('alert')).toHaveTextContent('Too many people looked up. Try again in a minute. (rate_limited · HTTP 429)')
    expect(dialog().getByLabelText('Email')).toHaveValue('bob@example.test')
  })

  test('acting as the owner: the shares are listed, nothing can be changed', async () => {
    h.user = { ...h.user, actingAs: { id: 'alice', name: 'Alice Owner', email: 'alice@example.test', accountType: 'member', reason: null, endsAt: null } }
    listAnswers.push(() => json({ collaborators: [share()] }))
    renderDialog()
    expect(await dialog().findByText(/cannot be changed while you act as another account/)).toBeInTheDocument()
    expect(dialog().getByLabelText('Email')).toBeDisabled()
    expect(dialog().getByRole('button', { name: 'Share' })).toBeDisabled()
    expect(dialog().queryByRole('button', { name: 'Revoke access for Bob Reader' })).toBeNull()
  })
})

describe('granting', () => {
  test('confirmed recipient shown: the account the server bound, as an IdentityLabel, with the preset', async () => {
    grantAnswer = () => json({ collaborator: share() }, 201)
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    listAnswers.push(() => json({ collaborators: [share()] }))
    fillEmail('  Bob@Example.test ')
    submit()
    const status = await dialog().findByRole('status', { name: 'Shared' })
    expect(within(status).getByRole('group', { name: 'Bob Reader, bob@example.test, Member' })).toBeInTheDocument()
    expect(status).toHaveTextContent('Viewer (Read)')
    expect(lastBody('POST')).toEqual({ email: 'Bob@Example.test', access: 'read', rawData: false })
    expect(dialog().getByLabelText('Email')).toHaveValue('')
    await waitFor(() => expect(calls('GET')).toHaveLength(2))
  })

  test('presets: Analyst sends Raw data; Custom sends the Raw data toggle', async () => {
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    fireEvent.click(dialog().getByRole('radio', { name: /^Analyst/ }))
    fillEmail('bob@example.test')
    submit()
    await waitFor(() => expect(calls('POST')).toHaveLength(1))
    expect(lastBody('POST')).toEqual({ email: 'bob@example.test', access: 'read', rawData: true })

    await dialog().findByRole('status', { name: 'Shared' })
    fireEvent.click(dialog().getByRole('radio', { name: /^Custom/ }))
    const raw = dialog().getByRole('checkbox', { name: /Raw data & files/ })
    expect(raw).not.toBeChecked()
    fireEvent.click(raw)
    fillEmail('carol@example.test')
    submit()
    await waitFor(() => expect(calls('POST')).toHaveLength(2))
    expect(lastBody('POST')).toEqual({ email: 'carol@example.test', access: 'read', rawData: true })
  })

  test('an end date and a note go with the grant; empty, neither is sent', async () => {
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    fillEmail('bob@example.test')
    fireEvent.change(dialog().getByLabelText(/Ends on/), { target: { value: '2027-01-31' } })
    fireEvent.change(dialog().getByLabelText(/Note/), { target: { value: 'Q1 pentest' } })
    submit()
    await waitFor(() => expect(calls('POST')).toHaveLength(1))
    expect(lastBody('POST')).toEqual({ email: 'bob@example.test', access: 'read', rawData: false, expiresAt: endOfDayIso('2027-01-31'), note: 'Q1 pentest' })
  })

  test('unknown email message: the server\'s answer, nothing more, and no recipient shown', async () => {
    grantAnswer = () => json({ error: 'No account has this email.', code: 'no_such_account' }, 404)
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    fillEmail('nobody@example.test')
    submit()
    const alert = await dialog().findByRole('alert')
    expect(alert).toHaveTextContent('No account has this email. (no_such_account · HTTP 404)')
    expect(dialog().queryByRole('status', { name: 'Shared' })).toBeNull()
    expect(dialog().queryByRole('group', { name: /nobody/ })).toBeNull()
  })

  test('an empty or malformed email is refused before any lookup', async () => {
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    submit()
    expect(await dialog().findByRole('alert')).toHaveTextContent("Enter the person's exact sign-in email")
    fillEmail('not-an-email')
    submit()
    expect(await dialog().findByRole('alert')).toHaveTextContent("Enter the person's exact sign-in email")
    expect(calls('POST')).toHaveLength(0)
  })

  test('a refusal naming a permission shows the permission notice', async () => {
    grantAnswer = () => json({ error: 'Forbidden', code: 'forbidden', permission: 'project:share' }, 403)
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    fillEmail('bob@example.test')
    submit()
    expect(await dialog().findByText('You do not have the permission this needs.')).toBeInTheDocument()
  })
})

describe('warnings and the Read + Write presets', () => {
  test('warnings: what Read shows always; Raw data\'s warning only while Raw data is chosen', async () => {
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    expect(dialog().getByText(/Every level shows what recon found as you see it/)).toBeInTheDocument()
    const rawWarning = 'Raw data includes captured traffic, workspace files and loot; grant it as you would hand over the files.'
    expect(dialog().queryByText(rawWarning)).toBeNull()
    fireEvent.click(dialog().getByRole('radio', { name: /^Analyst/ }))
    expect(dialog().getByText(rawWarning)).toBeInTheDocument()
    fireEvent.click(dialog().getByRole('radio', { name: /^Custom/ }))
    expect(dialog().queryByText(rawWarning)).toBeNull()
    fireEvent.click(dialog().getByRole('checkbox', { name: /Raw data & files/ }))
    expect(dialog().getByText(rawWarning)).toBeInTheDocument()
  })

  test('sandbox notice (HD-22) and the target credentials warning (SH-29) beside the write toggles', async () => {
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    const write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).getAllByText(/sandbox shared by every project on this server/).length).toBeGreaterThan(0)
    expect(within(write).getAllByText(/target credentials/).length).toBeGreaterThan(0)
  })

  test('write switch off: the four write presets disabled, "Coming when write sharing is on"', async () => {
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    const write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).getByText('Coming when write sharing is on')).toBeInTheDocument()
    for (const name of ['Editor', 'Operator', 'Red-teamer', 'Co-owner']) {
      expect(within(write).getByRole('radio', { name: new RegExp(`^${name}`) })).toBeDisabled()
    }
    for (const name of ['Run scans', 'Use AI agent', 'Exploitation & shells', 'Manage (co-owner)']) {
      expect(within(write).getByRole('checkbox', { name: new RegExp(`^${name.replace(/[()]/g, '\\$&')}`) })).toBeDisabled()
    }
  })

  test('write switch on: still disabled in this phase, saying why', async () => {
    h.user = { ...h.user, flags: { ...(h.user!.flags as object), sharingWrite: true }, sharing: { enabled: true, maxLevel: 'write' } }
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    const write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).getByText('Read + Write sharing is not available yet')).toBeInTheDocument()
    expect(within(write).getByRole('radio', { name: /^Editor/ })).toBeDisabled()
  })

  test('keyboard and labels: every control is named, Viewer chosen first, Escape closes', async () => {
    const onClose = renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    expect(dialog().getByRole('radiogroup', { name: 'Access' })).toBeInTheDocument()
    expect(dialog().getByRole('radio', { name: /^Viewer/ })).toBeChecked()
    expect(dialog().getByLabelText('Email')).toHaveAttribute('type', 'email')
    fireEvent.keyDown(screen.getByRole('dialog', { name: 'Share "Alpha recon"' }), { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })
})

describe('changing and revoking from the list', () => {
  test('revoke confirmation, then DELETE and the list again', async () => {
    listAnswers.push(() => json({ collaborators: [share()] }))
    renderDialog()
    fireEvent.click(await dialog().findByRole('button', { name: 'Revoke access for Bob Reader' }))
    const confirm = await screen.findByRole('dialog', { name: 'Revoke access' })
    expect(confirm).toHaveTextContent(/Bob Reader/)
    listAnswers.push(() => json({ collaborators: [] }))
    fireEvent.click(within(confirm).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(calls('DELETE')).toHaveLength(1))
    expect(await dialog().findByText('Not shared with anyone yet.')).toBeInTheDocument()
  })

  test('revoke: when the agent did not confirm the sockets closed, the dialog says so', async () => {
    listAnswers.push(() => json({ collaborators: [share()] }))
    socketsClosed = false
    renderDialog()
    fireEvent.click(await dialog().findByRole('button', { name: 'Revoke access for Bob Reader' }))
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Revoke access' })).getByRole('button', { name: 'Revoke' }))
    expect(await dialog().findByText(/could not confirm that their open connections closed/)).toBeInTheDocument()
  })

  test('change sends only what changed', async () => {
    listAnswers.push(() => json({ collaborators: [share()] }))
    renderDialog()
    fireEvent.click(await dialog().findByRole('button', { name: 'Change access for Bob Reader' }))
    const form = within(dialog().getByRole('form', { name: 'Change access for Bob Reader' }))
    expect(form.getByRole('radio', { name: /^Viewer/ })).toBeChecked()
    fireEvent.click(form.getByRole('radio', { name: /^Analyst/ }))
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(calls('PATCH')).toHaveLength(1))
    expect(lastBody('PATCH')).toEqual({ rawData: true })
  })
})
