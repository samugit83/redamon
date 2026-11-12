/**
 * The header's Root transfer banner (step 2.6, ID-07): with the identity switch on it reads the
 * pending offer (GET /api/root/transfer, which answers only Root and the recipient). The
 * recipient sees who offers Root and until when, accepts with its own password (both accounts
 * then sign in again: the browser goes to /login) or declines; Root sees its pending offer and may
 * cancel it. Declining and cancelling are confirmed through the app's dialog. No offer, a failed
 * read, the switch off or a member: nothing shown.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { AdminBanners } from './CompatBanner'
import { ROOT_TRANSFER_CHANGED_EVENT } from './RootTransferBanner'

const fetchMock = vi.fn()
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const ON = { compat: false, legacyGrantsPending: 0, identity: true as const, root: { email: 'root@x.z', confirmed: true, chosenAt: null } }
const OFFER = { toUserId: 'admin-2', toEmail: 'pia@x.z', fromEmail: 'root@x.z', expiresAt: '2026-11-13T10:00:00.000Z' }
const posts = () => fetchMock.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'POST')
const dialog = () => within(screen.getByRole('dialog'))

let offer: Record<string, unknown> | null = null

function show() {
  render(<AlertProvider><AdminBanners adminAccount rbac={ON} pathname="/graph" /></AlertProvider>)
}

beforeEach(() => {
  offer = null
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/root/transfer' && !init?.method) return json({ offer })
    return json({ withdrawn: true })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the recipient', () => {
  beforeEach(() => { offer = { ...OFFER, forYou: true } })

  test('sees who offers Root and until when, and accepts with its own password', async () => {
    const replace = vi.fn()
    vi.spyOn(window, 'location', 'get').mockReturnValue({ ...window.location, replace } as Location)
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) =>
      url === '/api/root/transfer' && !init?.method ? json({ offer }) : json({ transferred: true }))
    show()
    const banner = await screen.findByRole('status', { name: 'Root transfer offered to you' })
    expect(banner.textContent).toMatch(/root@x\.z offers you Root until 2026-11-13/)
    fireEvent.click(within(banner).getByRole('button', { name: 'Accept Root' }))
    expect(dialog().getByText(/sign in again/)).toBeInTheDocument()
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'pia-own-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Accept Root' }))
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/login'))
    expect(posts()[0][0]).toBe('/api/root/transfer/accept')
    expect(JSON.parse(String((posts()[0][1] as RequestInit).body))).toEqual({ stepUpPassword: 'pia-own-passphrase' })
  })

  test("a refused accept keeps the dialog open with the server's message and code", async () => {
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) =>
      url === '/api/root/transfer' && !init?.method
        ? json({ offer })
        : json({ error: 'The Root transfer offer has expired. Ask Root to offer it again.', code: 'transfer_expired' }, 409))
    show()
    fireEvent.click(await screen.findByRole('button', { name: 'Accept Root' }))
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'pia-own-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Accept Root' }))
    expect(await dialog().findByText(/has expired.*transfer_expired/)).toBeInTheDocument()
  })

  test('declining asks first, then withdraws the offer and the banner goes', async () => {
    show()
    fireEvent.click(await screen.findByRole('button', { name: 'Decline' }))
    expect(dialog().getByText(/Decline Root from root@x\.z\?/)).toBeInTheDocument()
    offer = null
    fireEvent.click(dialog().getByRole('button', { name: 'Decline' }))
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(posts()[0][0]).toBe('/api/root/transfer/cancel')
    expect((posts()[0][1] as RequestInit).body).toBe('{}')
    await waitFor(() => expect(screen.queryByRole('status', { name: /Root transfer/ })).toBeNull())
  })

  test('declining cancelled in the dialog: nothing sent', async () => {
    show()
    fireEvent.click(await screen.findByRole('button', { name: 'Decline' }))
    fireEvent.click(dialog().getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(posts()).toHaveLength(0)
  })
})

describe('Root', () => {
  test('sees its pending offer and cancels it', async () => {
    offer = { ...OFFER, forYou: false }
    show()
    const banner = await screen.findByRole('status', { name: 'Root transfer pending' })
    expect(banner.textContent).toMatch(/offered Root to pia@x\.z until 2026-11-13/)
    fireEvent.click(within(banner).getByRole('button', { name: 'Cancel the offer' }))
    offer = null
    fireEvent.click(dialog().getByRole('button', { name: 'Cancel the offer' }))
    await waitFor(() => expect(posts()[0]?.[0]).toBe('/api/root/transfer/cancel'))
    await waitFor(() => expect(screen.queryByRole('status', { name: /Root transfer/ })).toBeNull())
  })

  test('an offer made on the Users page shows at once (the change event reads it again)', async () => {
    show()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    offer = { ...OFFER, forYou: false }
    window.dispatchEvent(new Event(ROOT_TRANSFER_CHANGED_EVENT))
    expect(await screen.findByRole('status', { name: 'Root transfer pending' })).toBeInTheDocument()
  })
})

describe('nothing shown', () => {
  test('no offer', async () => {
    show()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(screen.queryByRole('status', { name: /Root transfer/ })).toBeNull()
  })

  test('a failed read', async () => {
    fetchMock.mockImplementation(async () => json({ error: 'boom', code: 'P1001' }, 500))
    show()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(screen.queryByRole('status', { name: /Root transfer/ })).toBeNull()
  })

  test('switch off, or a member: nothing is even asked', async () => {
    render(<AdminBanners adminAccount rbac={{ compat: false, legacyGrantsPending: 0 }} pathname="/graph" />)
    render(<AdminBanners adminAccount={false} rbac={ON} pathname="/graph" />)
    await new Promise((r) => setTimeout(r, 10))
    expect(fetchMock.mock.calls.filter((c) => c[0] === '/api/root/transfer')).toEqual([])
  })
})
