/**
 * The legacy access review card on the Users page (HD-29, §14.7, step 1.18): the members
 * that kept a shared tool at the upgrade, Keep or Remove per grant, Remove all
 * (recommended for shared servers), Keep all, Decide later. It never blocks anything: it
 * renders nothing while it loads or when nobody holds a grant, and an error is one line
 * with Retry. Every removal is confirmed through useAlertModal, since a removed grant
 * cannot be given back.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { LegacyAccessCard } from './LegacyAccessCard'
import { LEGACY_GRANTS_CHANGED_EVENT, type LegacyGrantsAnswer } from './updateNotes'

const fetchMock = vi.fn()
let listing: LegacyGrantsAnswer
let decisionAnswer: Record<string, unknown>

const MARCO = {
  id: 'member-1', name: 'Marco', email: 'marco@e2e.local',
  grants: [{ grant: 'kali_terminal' as const, state: 'pending' as const }, { grant: 'shell_sessions' as const, state: 'pending' as const }],
}
const ANNA = {
  id: 'member-2', name: 'Anna', email: 'anna@e2e.local',
  grants: [
    { grant: 'kali_terminal' as const, state: 'pending' as const },
    { grant: 'shell_sessions' as const, state: 'kept' as const },
    { grant: 'tunnels' as const, state: 'pending' as const },
  ],
}

beforeEach(() => {
  listing = { holders: [ANNA, MARCO], pending: 4 }
  decisionAnswer = { changed: true }
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/admin/legacy-grants' && (!init?.method || init.method === 'GET')) {
      return new Response(JSON.stringify(listing), { status: 200 })
    }
    if (url === '/api/admin/legacy-grants' && init?.method === 'POST') {
      return new Response(JSON.stringify(decisionAnswer), { status: 200 })
    }
    return new Response('{}', { status: 404 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderCard = () => render(<AlertProvider><LegacyAccessCard /></AlertProvider>)
const posts = () => fetchMock.mock.calls
  .filter(c => (c[1] as RequestInit | undefined)?.method === 'POST')
  .map(c => JSON.parse(String((c[1] as RequestInit).body)))

async function confirmDialog(label: string) {
  const dialog = await screen.findByRole('dialog')
  fireEvent.click(within(dialog).getByRole('button', { name: label }))
}

describe('card hidden without grants', () => {
  test('nobody holds a grant: nothing is rendered', async () => {
    listing = { holders: [], pending: 0 }
    const { container } = renderCard()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    await waitFor(() => expect(container.querySelector('section')).toBeNull())
    expect(container.textContent).toBe('')
  })

  test('nothing while it loads', () => {
    fetchMock.mockImplementation(() => new Promise(() => {}))
    const { container } = renderCard()
    expect(container.textContent).toBe('')
  })

  test('a 403 (not an admin) renders nothing', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'no', code: 'forbidden' }), { status: 403 }))
    const { container } = renderCard()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    await new Promise(r => setTimeout(r, 0))
    expect(container.textContent).toBe('')
  })

  test('an error is one line with its cause and Retry', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'Could not read', code: 'P1001' }), { status: 500 }))
    renderCard()
    const line = await screen.findByText(/Could not load the legacy access review/)
    expect(line.closest('[role="status"]')!.textContent).toMatch(/P1001 · HTTP 500/)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('region', { name: /kept access to shared tools/ })).toBeInTheDocument()
  })
})

describe('the review', () => {
  test('the §14.7 text, each holder and grant, labelled controls', async () => {
    renderCard()
    const card = await screen.findByRole('region', { name: '2 people kept access to shared tools from the previous version.' })
    expect(card.textContent).toContain("These tools let them reach other users' files and shells.")
    expect(card.textContent).toContain("Remove them on a server shared by people who should not see each other's work.")
    expect(within(card).getByText('Marco')).toBeInTheDocument()
    expect(within(card).getByText('anna@e2e.local')).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Keep Kali terminal for Marco' })).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Remove All shell sessions from Marco' })).toBeInTheDocument()
    // A kept grant shows as kept: only Remove is offered.
    expect(within(card).queryByRole('button', { name: 'Keep All shell sessions for Anna' })).toBeNull()
    expect(within(card).getByRole('button', { name: 'Remove All shell sessions from Anna' })).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Remove all (recommended for shared servers)' })).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Keep all' })).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Decide later' })).toBeInTheDocument()
  })

  test('Keep sends one keep decision, no dialog, then reads the list again and tells the header', async () => {
    const heard = vi.fn()
    window.addEventListener(LEGACY_GRANTS_CHANGED_EVENT, heard)
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Keep Kali terminal for Marco' }))
    await waitFor(() => expect(posts()).toEqual([{ action: 'keep', userId: 'member-1', grant: 'kali_terminal' }]))
    expect(screen.queryByRole('dialog')).toBeNull()
    await waitFor(() => expect(heard).toHaveBeenCalledTimes(1))
    expect(fetchMock.mock.calls.filter(c => !(c[1] as RequestInit | undefined)?.method)).toHaveLength(2)
    const post = fetchMock.mock.calls.find(c => (c[1] as RequestInit | undefined)?.method === 'POST')![1] as RequestInit
    expect(new Headers(post.headers).get('content-type')).toBe('application/json')
    window.removeEventListener(LEGACY_GRANTS_CHANGED_EVENT, heard)
  })

  test('Remove asks first; Cancel sends nothing', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Remove Kali terminal from Marco' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toMatch(/Marco loses it at once, and an open Kali terminal is closed/)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(posts()).toEqual([])
  })

  test('Remove confirmed sends one remove decision', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Remove Tunnel settings from Anna' }))
    await confirmDialog('Remove')
    await waitFor(() => expect(posts()).toEqual([{ action: 'remove', userId: 'member-2', grant: 'tunnels' }]))
  })

  test('a terminal the agent did not confirm closed is reported through the alert dialog', async () => {
    decisionAnswer = { changed: true, terminal: { error: 'agent_unreachable' } }
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Remove Kali terminal from Marco' }))
    await confirmDialog('Remove')
    const warning = await screen.findByRole('dialog')
    await waitFor(() => expect(warning.textContent).toMatch(/removed, but the agent did not confirm .*agent_unreachable/))
  })

  test('Remove all asks first and sends one remove_all', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Remove all (recommended for shared servers)' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toMatch(/Remove all 5 legacy grants of 2 people\?/)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove all' }))
    await waitFor(() => expect(posts()).toEqual([{ action: 'remove_all' }]))
  })

  test('Keep all sends one keep_all without a dialog', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Keep all' }))
    await waitFor(() => expect(posts()).toEqual([{ action: 'keep_all' }]))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('a refused decision is shown with its cause and the list is read again', async () => {
    renderCard()
    const keep = await screen.findByRole('button', { name: 'Keep Kali terminal for Marco' })
    fetchMock.mockImplementationOnce(async () => new Response(
      JSON.stringify({ error: 'This account no longer holds that grant.', code: 'not_held' }), { status: 409 },
    ))
    fireEvent.click(keep)
    const dialog = await screen.findByRole('dialog')
    await waitFor(() => expect(dialog.textContent).toMatch(/no longer holds that grant.*not_held · HTTP 409/))
    await waitFor(() => expect(fetchMock.mock.calls.filter(c => !(c[1] as RequestInit | undefined)?.method)).toHaveLength(2))
  })

  test('the controls are disabled while a decision is in flight', async () => {
    renderCard()
    const keep = await screen.findByRole('button', { name: 'Keep all' })
    fetchMock.mockImplementationOnce(() => new Promise(() => {}))
    fireEvent.click(keep)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Keep Kali terminal for Marco' })).toBeDisabled())
    expect(screen.getByRole('region', { name: /kept access/ })).toHaveAttribute('aria-busy', 'true')
  })

  test('Decide later folds the card to one line that opens it again; nothing is sent', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Decide later' }))
    expect(screen.queryByRole('button', { name: 'Keep all' })).toBeNull()
    expect(screen.getByText(/4 legacy grants wait for your review/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Review now' }))
    expect(screen.getByRole('button', { name: 'Keep all' })).toBeInTheDocument()
    expect(posts()).toEqual([])
  })
})

describe('everything decided', () => {
  test('only kept grants: a closed summary that still offers Remove, without the bulk buttons', async () => {
    listing = { holders: [{ ...MARCO, grants: MARCO.grants.map(g => ({ ...g, state: 'kept' as const })) }], pending: 0 }
    renderCard()
    const summary = await screen.findByText('1 person keeps access to shared tools from the previous version.')
    expect(summary.closest('details')).not.toHaveAttribute('open')
    expect(screen.queryByRole('button', { name: 'Keep all' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Remove all/ })).toBeNull()
    fireEvent.click(summary)
    fireEvent.click(screen.getByRole('button', { name: 'Remove Kali terminal from Marco' }))
    await confirmDialog('Remove')
    await waitFor(() => expect(posts()).toEqual([{ action: 'remove', userId: 'member-1', grant: 'kali_terminal' }]))
  })
})
