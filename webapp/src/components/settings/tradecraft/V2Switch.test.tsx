/**
 * The Tradecraft 2.0 (preview) switch: asked for, then saved through the settings route.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const alerts = vi.hoisted(() => ({ confirm: vi.fn(async () => true), dangerConfirm: vi.fn(async () => true), alert: vi.fn(), alertError: vi.fn(), alertWarning: vi.fn() }))
vi.mock('@/components/ui', async orig => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alerts }))

import { TURN_OFF_TEXT, TURN_ON_TEXT, V2Switch } from './V2Switch'

const fetchMock = vi.fn()
const onChange = vi.fn()
const SETTINGS = '/api/users/user-1/tradecraft-settings'
const renderSwitch = (enabled: boolean) => render(<ToastProvider><V2Switch userId="user-1" enabled={enabled} onChange={onChange} /></ToastProvider>)

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock.mockImplementation(async (_url: string, init?: RequestInit) => new Response(init?.body ?? '{}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('V2Switch', () => {
  test('asks_confirmation: turning it on says what changes and that turning it off returns to today', async () => {
    alerts.confirm.mockResolvedValueOnce(false)
    renderSwitch(false)
    fireEvent.click(screen.getByRole('switch', { name: 'Tradecraft 2.0 (preview)' }))
    await waitFor(() => expect(alerts.confirm).toHaveBeenCalledWith(TURN_ON_TEXT, 'Turn on Tradecraft 2.0 (preview)?'))
    expect(TURN_ON_TEXT).toMatch(/background/)
    expect(TURN_ON_TEXT).toMatch(/returns to today's behaviour/)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(onChange).not.toHaveBeenCalled()
  })

  test('calls_settings_route: confirmed, it PUTs exactly {v2Enabled} and reports the saved value', async () => {
    renderSwitch(false)
    fireEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(true))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect([url, init.method, init.body]).toEqual([SETTINGS, 'PUT', JSON.stringify({ v2Enabled: true })])
  })

  test('turning it off asks with its own text', async () => {
    renderSwitch(true)
    fireEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(false))
    expect(alerts.confirm).toHaveBeenCalledWith(TURN_OFF_TEXT, 'Turn off Tradecraft 2.0 (preview)?')
  })

  test('a refused save changes nothing and says why', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Forbidden', code: 'not_while_acting_as' }), { status: 403 }))
    renderSwitch(false)
    fireEvent.click(screen.getByRole('switch'))
    expect(await screen.findByText(/not_while_acting_as/)).toBeInTheDocument()
    expect(onChange).not.toHaveBeenCalled()
  })
})
