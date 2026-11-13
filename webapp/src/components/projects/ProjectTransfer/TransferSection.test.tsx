/**
 * The share dialog's "Transfer ownership" section (step 5.12; SH-15): shown to the owner only (GET
 * .../transfer `role: 'owner'`; anyone else, a 404, or the switch off: nothing). The owner picks one of
 * the active collaborators (an expired or inactive share is not offered), says whether they stay as a
 * co-owner or leave, reads what happens (the findings note, OQ-R8), and confirms with their password; an
 * open offer shows its end date and can be cancelled. Acting as someone: shown, never changed.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import type { ShareView } from '@/lib/authz/projectShares'
import { TransferSection } from './TransferSection'

const fetchMock = vi.fn()
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const posts = () => fetchMock.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'POST')
const dialog = () => within(screen.getByRole('dialog'))

const share = (id: string, name: string, over: Partial<ShareView> = {}): ShareView => ({
  user: { id, name, email: `${id}@e2e.local`, status: 'active', accountType: 'member' },
  access: 'read', rawData: false, expiresAt: null, expired: false, note: null, grantedById: 'u-old', grantedBy: null,
  createdAt: '2026-11-01T00:00:00.000Z', updatedAt: '2026-11-01T00:00:00.000Z', ...over,
})
const SHARES = [
  share('u-bob', 'Bob Collab'),
  share('u-gone', 'Expired Share', { expired: true }),
  share('u-off', 'Disabled Account', { user: { id: 'u-off', name: 'Disabled Account', email: 'off@e2e.local', status: 'disabled', accountType: 'member' } }),
]
const OFFER = {
  id: 't1', project: { id: 'p1', name: 'Client X' }, from: { id: 'u-old', name: 'Olga', email: 'olga@e2e.local' },
  to: { id: 'u-bob', name: 'Bob Collab', email: 'u-bob@e2e.local' }, oldOwnerRole: 'leave', status: 'pending', error: null,
  createdAt: '2026-11-10T10:00:00.000Z', expiresAt: '2026-11-17T10:00:00.000Z', decidedAt: null,
}

let state: { status: number; body: unknown } = { status: 200, body: { role: 'owner', offer: null, cleared: null } }

function show(shares: ShareView[] | null = SHARES, readOnly = false) {
  render(<AlertProvider><TransferSection project={{ id: 'p1', name: 'Client X' }} shares={shares} readOnly={readOnly} /></AlertProvider>)
}

beforeEach(() => {
  state = { status: 200, body: { role: 'owner', offer: null, cleared: null } }
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/projects/p1/transfer' && !init?.method) return json(state.body, state.status)
    return json({ offer: OFFER }, 201)
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the owner offers the project', () => {
  test('only active collaborators are offered; the offer needs a pick, says what happens and asks the password', async () => {
    show()
    const section = await screen.findByRole('region', { name: 'Transfer ownership' })
    const picker = within(section).getByLabelText('New owner') as HTMLSelectElement
    expect([...picker.options].map((o) => o.textContent)).toEqual(['Pick a collaborator', 'Bob Collab (u-bob@e2e.local)'])
    expect(section.textContent).toMatch(/settings that use your own LLM providers, Nuclei templates or GitHub token are cleared/)
    expect(section.textContent).toMatch(/records some findings it finds again/)
    const offer = within(section).getByRole('button', { name: 'Offer ownership...' })
    expect(offer).toBeDisabled()
    fireEvent.change(picker, { target: { value: 'u-bob' } })
    fireEvent.click(within(section).getByLabelText('Leave the project'))
    fireEvent.click(offer)
    expect(dialog().getByText(/you leave the project \(your conversations there stay with it/)).toBeInTheDocument()
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'olga-pass' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Offer' }))
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(posts()[0][0]).toBe('/api/projects/p1/transfer')
    expect(JSON.parse(posts()[0][1].body as string)).toEqual({ toUserId: 'u-bob', oldOwnerRole: 'leave', stepUpPassword: 'olga-pass' })
  })

  test('no active collaborator: says to share first', async () => {
    show([SHARES[1]])
    expect(await screen.findByText(/Share the project with a person first/)).toBeInTheDocument()
  })

  test('an open offer shows its end and is cancelled after confirming', async () => {
    state = { status: 200, body: { role: 'owner', offer: OFFER, cleared: null } }
    show()
    const callout = await screen.findByRole('status', { name: 'Ownership transfer offered' })
    expect(callout.textContent).toMatch(/Offered to Bob Collab \(u-bob@e2e\.local\) until Nov 17, 2026.*you then leave the project/)
    fireEvent.click(within(callout).getByRole('button', { name: 'Cancel the offer' }))
    fireEvent.click(dialog().getByRole('button', { name: 'Cancel the offer' }))
    await waitFor(() => expect(posts()[0]?.[0]).toBe('/api/projects/p1/transfer/cancel'))
  })

  test('acting as someone: shown, nothing can be offered or cancelled', async () => {
    show(SHARES, true)
    const section = await screen.findByRole('region', { name: 'Transfer ownership' })
    expect(within(section).getByLabelText('New owner')).toBeDisabled()
    expect(within(section).getByRole('button', { name: 'Offer ownership...' })).toBeDisabled()
  })
})

describe('not the owner, or not available', () => {
  test.each([
    ['a co-owner (role none)', { status: 200, body: { role: 'none', offer: null, cleared: null } }],
    ['the routes answer 404 (write sharing not in force)', { status: 404, body: { error: 'Not found' } }],
  ])('%s: the section is not shown', async (_what, answer) => {
    state = answer
    show()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    await new Promise((r) => setTimeout(r, 10))
    expect(screen.queryByRole('region', { name: 'Transfer ownership' })).toBeNull()
  })

  test('a failed read says so, with a retry', async () => {
    state = { status: 500, body: { error: 'down', code: 'P1001' } }
    show()
    expect(await screen.findByRole('alert')).toHaveTextContent(/down/)
    state = { status: 200, body: { role: 'owner', offer: null, cleared: null } }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByLabelText('New owner')).toBeInTheDocument()
  })
})
