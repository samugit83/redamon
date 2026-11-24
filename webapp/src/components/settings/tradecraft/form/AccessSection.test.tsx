/**
 * The Access section (§6.6, T6.11; R-141, R-151, R-157): the GitHub token override moved here,
 * cookies, custom headers and basic authentication; a stored value shows as "set", never as its
 * value; disabled while an administrator acts as the account; what the form sends.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { useEffect, useState } from 'react'

const auth = vi.hoisted(() => ({ value: null as null | { user: { actingAs: { id: string; name: string; email: string } | null } } }))
vi.mock('@/providers/AuthProvider', () => ({ useOptionalAuth: () => auth.value }))
vi.mock('@/components/shared/ModelPicker', () => ({
  ModelPicker: ({ value, onChange }: { value: string; onChange: (v: string) => void }) =>
    <input aria-label="Model" value={value} onChange={e => onChange(e.target.value)} />,
}))

import { AlertProvider } from '@/components/ui'
import { AccessSection, LOGIN_NOTE, accessDraftOf, accessError, accessStatus, credentialsPayload, type AccessDraft } from './AccessSection'
import { ResourceFormV2 } from './ResourceFormV2'
import { RESOURCE } from '../__testing__/resourceView'
import type { MaskedCredentials } from '@/lib/tradecraft/masking'

const STORED: MaskedCredentials = {
  cookie: 'set', headers: [{ name: 'X-Api-Key', value: 'set' }], basic_auth: { username: 'ada', password: 'set' },
}
let latest: AccessDraft
function Host({ credentials, tokenSet = false }: { credentials?: MaskedCredentials; tokenSet?: boolean }) {
  const [draft, setDraft] = useState(() => accessDraftOf(credentials))
  useEffect(() => { latest = draft })
  return <AccessSection draft={draft} onChange={setDraft} tokenSet={tokenSet} />
}
const open = () => fireEvent.click(screen.getByRole('button', { name: /^Access/ }))

const fetchMock = vi.fn()
beforeEach(() => {
  vi.clearAllMocks()
  auth.value = null
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ resource: null, job: null }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const sent = () => JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body))
const renderForm = (resource: typeof RESOURCE | null) =>
  render(<AlertProvider><ResourceFormV2 userId="user-1" resource={resource} onSaved={vi.fn()} onCancel={vi.fn()} /></AlertProvider>)

describe('AccessSection', () => {
  test('github_token: the override lives in Access; typed, it is sent; untouched, it is not (R-141)', async () => {
    renderForm({ ...RESOURCE, githubTokenOverride: 'set' })
    expect(screen.queryByLabelText('GitHub token override')).toBeNull()
    open()
    const token = screen.getByLabelText('GitHub token override')
    expect(token).toHaveAttribute('type', 'password')
    expect(token).toHaveAttribute('placeholder', 'A token is set: type a new one to replace it')
    expect(screen.getByRole('button', { name: /^Access/ })).toHaveTextContent('GitHub token · no cookies or headers')
    fireEvent.change(token, { target: { value: 'ghp_fake' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(sent()).toMatchObject({ githubTokenOverride: 'ghp_fake' })
    expect(sent()).not.toHaveProperty('credentials')
  })

  test('shows_set_only: a stored cookie, header value and password read "set", never a value (R-157)', () => {
    render(<Host credentials={STORED} />)
    open()
    expect(screen.getByRole('button', { name: /^Access/ })).toHaveTextContent('no GitHub token · cookie, 1 header, basic authentication')
    for (const input of screen.getAllByDisplayValue('')) {
      if (input.getAttribute('type') === 'password') expect((input as HTMLInputElement).value).toBe('')
    }
    expect(screen.queryByDisplayValue('set')).toBeNull()
    expect(screen.getByLabelText('Cookies')).toHaveAttribute('placeholder', 'set: type a new value to replace it')
    expect(screen.getByLabelText('Header 1 name')).toHaveValue('X-Api-Key')
    expect(screen.getByLabelText('Header 1 value')).toHaveAttribute('placeholder', 'set: type a new value to replace it')
    expect(screen.getByLabelText('User name')).toHaveValue('ada')
    expect(screen.getByLabelText('Password')).toHaveAttribute('placeholder', 'set: type a new value to replace it')
    expect(screen.getByText(LOGIN_NOTE)).toBeInTheDocument()
    // Nothing changed: nothing to send; the kept values travel as "set", which keeps them.
    expect(credentialsPayload(accessDraftOf(STORED), latest)).toBeUndefined()
    fireEvent.change(screen.getByLabelText('User name'), { target: { value: 'grace' } })
    expect(credentialsPayload(accessDraftOf(STORED), latest)).toEqual({
      cookie: 'set', headers: [{ name: 'X-Api-Key', value: 'set' }], basic_auth: { username: 'grace', password: 'set' },
    })
  })

  test('cookies, headers and basic authentication typed in an Add are sent in the contract\'s names', async () => {
    renderForm(null)
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'KB' } })
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://kb.tc-fixture.test/' } })
    fireEvent.change(screen.getByLabelText('Model'), { target: { value: 'gpt-4o' } })
    open()
    fireEvent.change(screen.getByLabelText('Cookies'), { target: { value: 'cookie=fake-session' } })
    fireEvent.click(screen.getByRole('button', { name: /Add a header/ }))
    fireEvent.change(screen.getByLabelText('Header 1 name'), { target: { value: 'X-Api-Key' } })
    fireEvent.change(screen.getByLabelText('Header 1 value'), { target: { value: 'fake-key' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Basic authentication' }))
    fireEvent.change(screen.getByLabelText('User name'), { target: { value: 'ada' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'fake-pass' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(sent().credentials).toEqual({
      cookie: 'cookie=fake-session', headers: [{ name: 'X-Api-Key', value: 'fake-key' }], basic_auth: { username: 'ada', password: 'fake-pass' },
    })
  })

  test('removing everything sends null, which removes the login; a bad header is refused in the form', async () => {
    renderForm({ ...RESOURCE, hasLogin: true, credentials: { cookie: 'set', headers: [], basic_auth: null } })
    open()
    fireEvent.click(screen.getByRole('button', { name: 'Remove the cookie' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add a header' }))
    fireEvent.change(screen.getByLabelText('Header 1 name'), { target: { value: 'Bad Name' } })
    expect(screen.getByRole('alert')).toHaveTextContent('Bad Name is not a header name')
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findAllByRole('alert')).toHaveLength(2)
    expect(fetchMock).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Remove header 1' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(sent().credentials).toBeNull()
  })

  test('act_as_disabled: "Not available while acting as <name>", every field disabled', () => {
    auth.value = { user: { actingAs: { id: 'u2', name: 'Ada', email: 'ada@example.test' } } }
    render(<Host credentials={STORED} tokenSet />)
    open()
    expect(screen.getByRole('note')).toHaveTextContent('Not available while acting as Ada')
    expect(screen.getByLabelText('GitHub token override')).toBeDisabled()
    expect(screen.getByLabelText('Cookies')).toBeDisabled()
    expect(screen.getByLabelText('Header 1 value')).toBeDisabled()
    expect(screen.getByRole('button', { name: /Add a header/ })).toBeDisabled()
    expect(screen.getByLabelText('Password')).toBeDisabled()
  })

  test('the inline checks and the status line', () => {
    const d = accessDraftOf(undefined)
    expect(accessStatus(d, false)).toBe('no GitHub token · no cookies or headers')
    expect(accessError({ ...d, headers: [{ name: 'X-A', value: 'v' }, { name: 'x-a', value: 'w' }] })).toBe('The header x-a is named twice')
    expect(accessError({ ...d, basic: { username: 'a:b', password: 'p' } })).toBe('A user name cannot hold ":"')
    expect(accessError({ ...d, basic: { username: 'ada', password: '' } })).toBe('Type the basic authentication password')
    expect(accessError({ ...d, headers: [{ name: '', value: '' }] })).toBe('')
  })
})
