/**
 * The share dialog (steps 4.12, 5.14; UI-07, SH-05, SH-20, SH-29, HD-22, ID-25, ID-31; E2E P4-01,
 * P4-02, P4-04, P5-01, P5-02): an owner shares a project by exact email with a preset (Viewer, Analyst,
 * Custom; with write sharing in force Editor, Operator, Red-teamer, Co-owner and Custom's toggles), an
 * optional end date and a note, sees the person the server bound as an IdentityLabel, and lists,
 * changes and revokes the shares. With write sharing not in force the Read + Write presets are offered
 * disabled. Within it: the consent prompt, the step-up for Exploitation & shells, Root's policy limits,
 * the co-owner cap and the warnings. States: loading, empty, error, denied, sharing unavailable,
 * rate-limited, acting as the owner. The routes are 4.4's (fetch is the double); confirmations are the
 * real AlertProvider and StepUpModal.
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

  // By design (step 5.14, SH-05/UI-07): 4.12 kept the write presets disabled with the switch on; 5.14 opens them.
  test("write switch on: Root's policy at Read keeps them disabled, saying why; at write they are offered", async () => {
    h.user = { ...h.user, flags: { ...(h.user!.flags as object), sharingWrite: true }, sharing: { enabled: true, maxLevel: 'read' } }
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    let write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).getByText('The instance sharing policy allows Read shares only')).toBeInTheDocument()
    expect(within(write).getByRole('radio', { name: /^Editor/ })).toBeDisabled()
    cleanup()

    h.user = { ...h.user, sharing: { enabled: true, maxLevel: 'write' } }
    renderDialog()
    await dialog().findByText('Not shared with anyone yet.')
    write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).queryByText(/allows Read shares only|Coming when/)).toBeNull()
    for (const name of ['Editor', 'Operator', 'Red-teamer', 'Co-owner']) {
      expect(within(write).getByRole('radio', { name: new RegExp(`^${name}`) })).toBeEnabled()
    }
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

// Step 5.12: the owner's "Transfer ownership" section, only with write sharing in force; it lists the dialog's
// shares as the people the project can go to, and nothing about a transfer is asked otherwise (DV-30).
describe('the ownership transfer section (step 5.12)', () => {
  const transferGets = () => h.fetch.mock.calls.filter(([url, init]) => url === '/api/projects/P1/transfer' && !(init as RequestInit | undefined)?.method)

  test('write sharing in force: the owner gets the section, with the dialog\'s collaborators to pick from', async () => {
    h.user = { ...h.user!, sharing: { enabled: true, maxLevel: 'write' } }
    listAnswers.push(() => json({ collaborators: [share()] }))
    const base = h.fetch.getMockImplementation()!
    h.fetch.mockImplementation(async (url: string, init?: RequestInit) =>
      url === '/api/projects/P1/transfer' && !init?.method ? json({ role: 'owner', offer: null, cleared: null }) : base(url, init))
    renderDialog()
    const section = await dialog().findByRole('region', { name: 'Transfer ownership' })
    await waitFor(() => expect(within(section).getByRole('option', { name: 'Bob Reader (bob@example.test)' })).toBeInTheDocument())
  })

  test("Root's policy at Read: no section, and the transfer state is never asked", async () => {
    listAnswers.push(() => json({ collaborators: [share()] }))
    renderDialog()
    await dialog().findByRole('button', { name: 'Revoke access for Bob Reader' })
    expect(dialog().queryByRole('region', { name: 'Transfer ownership' })).toBeNull()
    expect(transferGets()).toEqual([])
  })
})


// Step 5.14: with write sharing in force (the switch and Root's policy at write) the list answers what the
// person may grant (`grantable`), and the dialog grants Read + Write: the consent prompt for a spend toggle
// the owner has not allowed yet (POST .../access-policy with the password, step 5.6), the step-up for
// Exploitation & shells (the password goes with the grant), one prompt when both apply; Root's policy limits
// shown disabled with why; a co-owner offered only what they hold; the warnings.
describe('Read + Write grants (step 5.14)', () => {
  const OK = { grantable: true }
  const grantable = (over: Record<string, unknown> = {}) => ({
    grantor: 'owner', ownerConsent: false, toggles: { runScans: OK, useAgent: OK, exploit: OK, manage: OK }, ...over,
  })
  let consentAnswer: () => Response
  let patchAnswer: () => Response

  beforeEach(() => {
    h.user = { ...h.user!, flags: { ...(h.user!.flags as object), sharingWrite: true }, sharing: { enabled: true, maxLevel: 'write' } }
    consentAnswer = () => json({ ownerCredentialConsent: true, consentAt: '2026-11-13T12:00:00.000Z', changed: true })
    patchAnswer = () => json({ collaborator: share() })
    const base = h.fetch.getMockImplementation()!
    h.fetch.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === '/api/projects/P1/transfer' && !init?.method) return json({ role: 'none', offer: null })
      if (url === '/api/projects/P1/access-policy' && init?.method === 'POST') return consentAnswer()
      if (url === '/api/projects/P1/collaborators/bob' && init?.method === 'PATCH') return patchAnswer()
      return base(url, init)
    })
  })

  const ready = async (answer: Record<string, unknown> = { collaborators: [], grantable: grantable() }) => {
    listAnswers.push(() => json(answer))
    renderDialog()
    await dialog().findByRole('group', { name: /Read \+ Write/ })
    await waitFor(() => expect(calls('GET').length).toBeGreaterThan(0))
  }
  const consentPosts = () => calls('POST').filter(([url]) => url === '/api/projects/P1/access-policy')
  const grantPosts = () => calls('POST').filter(([url]) => url === '/api/projects/P1/collaborators')
  const bodyOf = (call: unknown[]) => JSON.parse(String((call[1] as RequestInit).body))
  const prompt = (name: string) => screen.findByRole('dialog', { name })
  const typePassword = async (box: HTMLElement, value: string, button: string) => {
    fireEvent.change(within(box).getByLabelText('Your password'), { target: { value } })
    fireEvent.click(within(box).getByRole('button', { name: button }))
  }

  test('presets: Editor sends Read + Write without a toggle and asks no password', async () => {
    await ready()
    fireEvent.click(dialog().getByRole('radio', { name: /^Editor/ }))
    fillEmail('bob@example.test')
    submit()
    await waitFor(() => expect(grantPosts()).toHaveLength(1))
    expect(bodyOf(grantPosts()[0])).toEqual({
      email: 'bob@example.test', access: 'write', rawData: true, runScans: false, useAgent: false, exploit: false, manage: false,
    })
    expect(consentPosts()).toHaveLength(0)
    expect(screen.queryByRole('dialog', { name: /Allow spending|Grant Exploitation/ })).toBeNull()
  })

  test('consent prompt: Operator before the owner allowed it asks the consent with the password, then shares', async () => {
    await ready()
    expect(dialog().getByRole('status', { name: 'Spending your credentials' })).toHaveTextContent(/cannot spend this project's credentials yet/)
    fireEvent.click(dialog().getByRole('radio', { name: /^Operator/ }))
    fillEmail('bob@example.test')
    submit()
    const box = await prompt('Allow spending your credentials')
    expect(box).toHaveTextContent(/spend this project's credentials/)
    expect(grantPosts()).toHaveLength(0)
    await typePassword(box, 'pw-1', 'Allow and share')
    await waitFor(() => expect(grantPosts()).toHaveLength(1))
    expect(bodyOf(consentPosts()[0])).toEqual({ ownerCredentialConsent: true, stepUpPassword: 'pw-1' })
    // The consent is the owner's step-up; the grant itself carries no password (no Exploitation).
    expect(bodyOf(grantPosts()[0])).toMatchObject({ access: 'write', runScans: true, useAgent: true, exploit: false })
    expect(bodyOf(grantPosts()[0])).not.toHaveProperty('stepUpPassword')
    await dialog().findByRole('status', { name: 'Shared' })
  })

  test('consent prompt cancelled: nothing is sent and the form says so', async () => {
    await ready()
    fireEvent.click(dialog().getByRole('radio', { name: /^Operator/ }))
    fillEmail('bob@example.test')
    submit()
    fireEvent.click(within(await prompt('Allow spending your credentials')).getByRole('button', { name: 'Cancel' }))
    expect(await dialog().findByRole('alert')).toHaveTextContent('Not shared: the password was not confirmed.')
    expect(consentPosts()).toHaveLength(0)
    expect(grantPosts()).toHaveLength(0)
  })

  test('step-up for exploit: Red-teamer asks the password; a wrong one keeps the prompt open; the right one goes with the grant', async () => {
    await ready({ collaborators: [], grantable: grantable({ ownerConsent: true }) })
    fireEvent.click(dialog().getByRole('radio', { name: /^Red-teamer/ }))
    fillEmail('bob@example.test')
    grantAnswer = () => json({ error: 'Password is incorrect', code: 'step_up_failed' }, 403)
    submit()
    const box = await prompt('Grant Exploitation & shells')
    expect(box).toHaveTextContent(/approve exploitation and dangerous tools/)
    await typePassword(box, 'wrong', 'Share')
    expect(await within(box).findByRole('alert')).toHaveTextContent('Password is incorrect')
    grantAnswer = () => json({ collaborator: share({ access: 'write', rawData: true }) }, 201)
    await typePassword(box, 'right', 'Share')
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Grant Exploitation & shells' })).toBeNull())
    expect(bodyOf(grantPosts().at(-1)!)).toMatchObject({ access: 'write', exploit: true, stepUpPassword: 'right' })
    expect(consentPosts()).toHaveLength(0)
  })

  test('consent and step-up together: one prompt, the consent first, then the grant with the same password', async () => {
    await ready()
    fireEvent.click(dialog().getByRole('radio', { name: /^Co-owner/ }))
    fillEmail('bob@example.test')
    submit()
    const box = await prompt('Allow spending your credentials')
    expect(box).toHaveTextContent(/approve exploitation/)
    await typePassword(box, 'pw-2', 'Allow and share')
    await waitFor(() => expect(grantPosts()).toHaveLength(1))
    expect(bodyOf(consentPosts()[0])).toEqual({ ownerCredentialConsent: true, stepUpPassword: 'pw-2' })
    expect(bodyOf(grantPosts()[0])).toMatchObject({ manage: true, exploit: true, stepUpPassword: 'pw-2' })
  })

  test("policy limits: Exploitation kept to admins is disabled with Root's reason, and so are Red-teamer and Co-owner", async () => {
    const reason = 'The instance sharing policy lets only administrators grant Exploitation & shells.'
    await ready({ collaborators: [], grantable: grantable({ toggles: { runScans: OK, useAgent: OK, manage: OK, exploit: { grantable: false, code: 'exploit_admins_only', reason } } }) })
    const write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).getByRole('checkbox', { name: /^Exploitation & shells/ })).toBeDisabled()
    expect(within(write).getByRole('radio', { name: /^Red-teamer/ })).toBeDisabled()
    expect(within(write).getByRole('radio', { name: /^Co-owner/ })).toBeDisabled()
    expect(within(write).getByRole('radio', { name: /^Operator/ })).toBeEnabled()
    expect(within(write).getAllByText(new RegExp(reason.replace(/[.&]/g, '\\$&'))).length).toBeGreaterThan(0)
  })

  test("co-owner cap: a co-owner sees only what they hold, and no Change or Revoke on a co-owner's share", async () => {
    const notHeld = { grantable: false, code: 'not_held', reason: 'You do not hold it.' }
    await ready({
      collaborators: [share({ access: 'write', rawData: true, runScans: true, useAgent: false, exploit: false, manage: true, user: { id: 'carol', name: 'Carol Coowner', email: 'carol@example.test', status: 'active', accountType: 'member' } })],
      grantable: grantable({ grantor: 'co_owner', ownerConsent: true, toggles: { runScans: OK, manage: OK, useAgent: notHeld, exploit: notHeld } }),
    })
    const write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).queryByRole('checkbox', { name: /^Use AI agent/ })).toBeNull()
    expect(within(write).queryByRole('checkbox', { name: /^Exploitation & shells/ })).toBeNull()
    expect(within(write).getByRole('checkbox', { name: /^Run scans/ })).toBeEnabled()
    for (const name of ['Operator', 'Red-teamer', 'Co-owner']) expect(within(write).queryByRole('radio', { name: new RegExp(`^${name}`) })).toBeNull()
    expect(within(write).getByRole('radio', { name: /^Editor/ })).toBeEnabled()
    expect(dialog().queryByRole('status', { name: 'Spending your credentials' })).toBeNull()
    const carol = within(dialog().getByRole('listitem', { name: 'Carol Coowner' }))
    expect(carol.queryByRole('button', { name: /Change access/ })).toBeNull()
    expect(carol.queryByRole('button', { name: /Revoke access/ })).toBeNull()
    expect(carol.getByText(/Only the project's owner can change or revoke a co-owner's share/)).toBeInTheDocument()
    expect(carol.getByText('Toggles: Raw data & files, Run scans, Manage (co-owner)')).toBeInTheDocument()
  })

  test('warnings shown: the copy warning with Read + Write; the shared sandbox and the target credentials beside their toggles', async () => {
    await ready()
    expect(dialog().queryByText(/can copy what they see/)).toBeNull()
    fireEvent.click(dialog().getByRole('radio', { name: /^Editor/ }))
    expect(dialog().getByText(/can copy what they see/)).toBeInTheDocument()
    const write = dialog().getByRole('group', { name: /Read \+ Write/ })
    expect(within(write).getByRole('checkbox', { name: /^Use AI agent/ })).toHaveAccessibleDescription(/sandbox shared by every project.*target credentials/)
    expect(within(write).getByRole('checkbox', { name: /^Run scans/ })).toHaveAccessibleDescription(/target credentials/)
  })

  test('Custom: the level and each toggle; a toggle flipped from a preset moves to the preset it makes', async () => {
    await ready({ collaborators: [], grantable: grantable({ ownerConsent: true }) })
    fireEvent.click(dialog().getByRole('radio', { name: /^Operator/ }))
    fireEvent.click(dialog().getByRole('checkbox', { name: /^Run scans/ }))
    expect(dialog().getByRole('radio', { name: /^Custom/ })).toBeChecked()
    fireEvent.click(dialog().getByRole('checkbox', { name: /^Run scans/ }))
    expect(dialog().getByRole('radio', { name: /^Custom/ })).toBeChecked()
    fireEvent.click(dialog().getByRole('radio', { name: /^Viewer/ }))
    fireEvent.click(dialog().getByRole('checkbox', { name: /^Manage/ }))
    expect(dialog().getByRole('radio', { name: /^Custom/ })).toBeChecked()
    expect(dialog().getByRole('checkbox', { name: /^Read \+ Write/ })).toBeChecked()
    expect(dialog().getByRole('checkbox', { name: /Raw data & files/ })).toBeDisabled()
    fillEmail('bob@example.test')
    submit()
    await waitFor(() => expect(grantPosts()).toHaveLength(1))
    expect(bodyOf(grantPosts()[0])).toMatchObject({ access: 'write', rawData: true, runScans: false, useAgent: false, exploit: false, manage: true })
  })

  test('the owner withdraws the consent from the dialog (confirmed first)', async () => {
    await ready({ collaborators: [], grantable: grantable({ ownerConsent: true }) })
    listAnswers.push(() => json({ collaborators: [], grantable: grantable() }))
    const line = dialog().getByRole('status', { name: 'Spending your credentials' })
    fireEvent.click(within(line).getByRole('button', { name: 'Withdraw' }))
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Withdraw your consent' })).getByRole('button', { name: 'Withdraw' }))
    await waitFor(() => expect(consentPosts()).toHaveLength(1))
    expect(bodyOf(consentPosts()[0])).toEqual({ ownerCredentialConsent: false })
    await waitFor(() => expect(dialog().getByRole('status', { name: 'Spending your credentials' })).toHaveTextContent(/cannot spend/))
  })

  test('change: turning Exploitation on asks the password and the PATCH carries it; lowering to Viewer sends the level only', async () => {
    const operatorShare = share({ access: 'write', rawData: true, runScans: true, useAgent: true, exploit: false, manage: false })
    await ready({ collaborators: [operatorShare], grantable: grantable({ ownerConsent: true }) })
    listAnswers.push(() => json({ collaborators: [operatorShare], grantable: grantable({ ownerConsent: true }) }))
    fireEvent.click(dialog().getByRole('button', { name: 'Change access for Bob Reader' }))
    let form = within(dialog().getByRole('form', { name: 'Change access for Bob Reader' }))
    expect(form.getByRole('radio', { name: /^Operator/ })).toBeChecked()
    fireEvent.click(form.getByRole('radio', { name: /^Red-teamer/ }))
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    await typePassword(await prompt('Grant Exploitation & shells'), 'pw-3', 'Save')
    await waitFor(() => expect(calls('PATCH')).toHaveLength(1))
    expect(lastBody('PATCH')).toEqual({ exploit: true, stepUpPassword: 'pw-3' })

    await waitFor(() => expect(dialog().queryByRole('form', { name: 'Change access for Bob Reader' })).toBeNull())
    fireEvent.click(dialog().getByRole('button', { name: 'Change access for Bob Reader' }))
    form = within(dialog().getByRole('form', { name: 'Change access for Bob Reader' }))
    fireEvent.click(form.getByRole('radio', { name: /^Viewer/ }))
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(calls('PATCH')).toHaveLength(2))
    expect(lastBody('PATCH')).toEqual({ access: 'read', rawData: false })
  })
})
