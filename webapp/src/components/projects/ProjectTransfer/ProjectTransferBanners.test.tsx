/**
 * The header's ownership transfer banners (step 5.12; SH-15): only while write sharing is in force
 * (/api/auth/me's `sharing` at Read + Write), from GET /api/projects/transfers. The recipient sees who
 * offers which project and until when, accepts with their own password or declines (confirmed); the
 * owner sees their offer and may cancel it; the new owner sees the settings the transfer cleared, to
 * re-pick, and the note on findings recorded anew (OQ-R8), until they dismiss it. Acting as someone
 * shows and offers nothing to do. Write sharing not in force: nothing is fetched or shown (DV-30).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { ProjectTransferBanners } from './ProjectTransferBanners'

const fetchMock = vi.fn()
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const posts = () => fetchMock.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'POST')
const dialog = () => within(screen.getByRole('dialog'))

const OLGA = { id: 'u-old', name: 'Olga Owner', email: 'olga@e2e.local' }
const BOB = { id: 'u-new', name: 'Bob Collab', email: 'bob@e2e.local' }
const OFFER = {
  id: 't1', project: { id: 'p1', name: 'Client X' }, from: OLGA, to: BOB, oldOwnerRole: 'co-owner', status: 'pending', error: null,
  createdAt: '2026-11-10T10:00:00.000Z', expiresAt: '2026-11-17T10:00:00.000Z', decidedAt: null,
}
const CLEARED = {
  transferId: 't0', project: { id: 'p2', name: 'Client Y' }, from: OLGA, completedAt: '2026-11-12T10:00:00.000Z',
  cleared: [
    { field: 'agentOpenaiModel', label: 'Agent model', values: ["Olga's OpenAI-compatible"] },
    { field: 'nucleiSelectedCustomTemplates', label: 'Nuclei custom templates selected', values: ['old/own.yaml'] },
    { field: 'cypherfixGithubToken', label: 'CypherFix GitHub token' },
  ],
}

let feed: Record<string, unknown> = { incoming: [], outgoing: [], cleared: [] }

type Sharing = { enabled: boolean; maxLevel: 'read' | 'write' } | 'absent'

function show(sharing: Sharing = { enabled: true, maxLevel: 'write' }, actingAs: unknown = null) {
  const auth = fakeAuth({ ...FLAGS_ON, sharing: true, sharingWrite: true }, [])
  auth.user = { ...auth.user!, ...(sharing === 'absent' ? {} : { sharing }), actingAs: actingAs as never }
  render(<AuthContext.Provider value={auth}><AlertProvider><ProjectTransferBanners /></AlertProvider></AuthContext.Provider>)
}

beforeEach(() => {
  feed = { incoming: [], outgoing: [], cleared: [] }
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/projects/transfers' && !init?.method) return json(feed)
    return json({ ok: true })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the recipient', () => {
  test('sees who offers which project until when, and accepts with their own password', async () => {
    feed = { ...feed, incoming: [OFFER] }
    show()
    const banner = await screen.findByRole('status', { name: 'Ownership of Client X offered to you' })
    expect(banner.textContent).toMatch(/Olga Owner \(olga@e2e\.local\) offers you ownership of Client X until Nov 17, 2026; they stays on as a co-owner/)
    fireEvent.click(within(banner).getByRole('button', { name: 'Accept' }))
    expect(dialog().getByText(/spend your keys/)).toBeInTheDocument()
    expect(dialog().getByText(/must have nothing running/)).toBeInTheDocument()
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'bob-own-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Accept' }))
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(posts()[0][0]).toBe('/api/projects/p1/transfer/accept')
    expect(JSON.parse(posts()[0][1].body as string)).toEqual({ stepUpPassword: 'bob-own-passphrase' })
  })

  test('a busy project keeps the dialog open with the server\'s reason', async () => {
    feed = { ...feed, incoming: [OFFER] }
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === '/api/projects/transfers' && !init?.method) return json(feed)
      return json({ error: 'The project cannot change owner while a full recon scan is running.', code: 'project_busy' }, 409)
    })
    show()
    fireEvent.click(within(await screen.findByRole('status', { name: /offered to you/ })).getByRole('button', { name: 'Accept' }))
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'pw' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Accept' }))
    expect(await dialog().findByText(/a full recon scan is running/)).toBeInTheDocument()
  })

  test('declines after confirming', async () => {
    feed = { ...feed, incoming: [OFFER] }
    show()
    fireEvent.click(within(await screen.findByRole('status', { name: /offered to you/ })).getByRole('button', { name: 'Decline' }))
    expect(dialog().getByText(/Olga Owner \(olga@e2e\.local\) stays its owner/)).toBeInTheDocument()
    fireEvent.click(dialog().getByRole('button', { name: 'Decline' }))
    await waitFor(() => expect(posts()[0]?.[0]).toBe('/api/projects/p1/transfer/decline'))
  })
})

describe('the owner and the new owner', () => {
  test('the owner sees the offer and cancels it after confirming', async () => {
    feed = { ...feed, outgoing: [OFFER] }
    show()
    const banner = await screen.findByRole('status', { name: 'Ownership of Client X offered' })
    expect(banner.textContent).toMatch(/You offered Client X to Bob Collab \(bob@e2e\.local\) until Nov 17, 2026/)
    fireEvent.click(within(banner).getByRole('button', { name: 'Cancel the offer' }))
    fireEvent.click(dialog().getByRole('button', { name: 'Cancel the offer' }))
    await waitFor(() => expect(posts()[0]?.[0]).toBe('/api/projects/p1/transfer/cancel'))
  })

  test('the new owner sees every cleared setting by name, the findings note, and dismisses it', async () => {
    feed = { ...feed, cleared: [CLEARED] }
    show()
    const banner = await screen.findByRole('status', { name: 'Settings to re-pick on Client Y' })
    const items = within(banner).getAllByRole('listitem').map((li) => li.textContent)
    expect(items).toEqual(["Agent model: Olga's OpenAI-compatible", 'Nuclei custom templates selected: old/own.yaml', 'CypherFix GitHub token'])
    expect(banner.textContent).toMatch(/records some findings it finds again .* as new entries/)
    expect(banner.textContent).toMatch(/does not carry over/)
    fireEvent.click(within(banner).getByRole('button', { name: 'Dismiss' }))
    await waitFor(() => expect(posts()[0]?.[0]).toBe('/api/projects/p2/transfer/acknowledge'))
  })

  test('acting as someone: the banners show, with nothing to do', async () => {
    feed = { incoming: [OFFER], outgoing: [], cleared: [CLEARED] }
    show({ enabled: true, maxLevel: 'write' }, { id: 'u-new', name: 'Bob Collab', email: 'bob@e2e.local' })
    await screen.findByRole('status', { name: /offered to you/ })
    expect(screen.queryAllByRole('button')).toEqual([])
  })
})

describe('write sharing not in force (DV-30)', () => {
  test.each([
    ['sharing off (no sharing key)', 'absent' as const],
    ["Root's policy at Read", { enabled: true, maxLevel: 'read' as const }],
    ['sharing disabled', { enabled: false, maxLevel: 'write' as const }],
  ])('%s: nothing is fetched or shown', async (_what, sharing) => {
    feed = { incoming: [OFFER], outgoing: [OFFER], cleared: [CLEARED] }
    show(sharing)
    await new Promise((r) => setTimeout(r, 20))
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.queryByRole('status')).toBeNull()
  })

  test('a failed read shows nothing', async () => {
    fetchMock.mockResolvedValue(json({ error: 'down' }, 500))
    show()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(screen.queryByRole('status')).toBeNull()
  })
})
