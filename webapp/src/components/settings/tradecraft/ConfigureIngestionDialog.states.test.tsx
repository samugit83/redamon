/**
 * Configure ingestion's states (D-14): loading, a failure with Retry, denied, and 2.0 off.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { ConfigureIngestionDialog, APPLIES_TEXT } from './ConfigureIngestionDialog'
import { SETTINGS } from '@/lib/tradecraft/settingsSpec'

const DEFAULTS = Object.fromEntries(SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource').map(s => [s.key, s.default]))
const VIEW = { values: DEFAULTS, changed: [], defaults: DEFAULTS }
const fetchMock = vi.fn()
const onClose = vi.fn()

beforeEach(() => { vi.clearAllMocks(); vi.stubGlobal('fetch', fetchMock) })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const renderDialog = () => render(<AlertProvider><ConfigureIngestionDialog userId="user-1" onClose={onClose} onSaved={vi.fn()} /></AlertProvider>)

describe('ConfigureIngestionDialog states', () => {
  test('loading, then the settings', async () => {
    let release!: (r: Response) => void
    fetchMock.mockImplementationOnce(() => new Promise<Response>(r => { release = r }))
    renderDialog()
    expect(screen.getByText('Loading your settings…')).toBeInTheDocument()
    release(answer(200, { v2Enabled: true, ingestion: VIEW }))
    expect(await screen.findByText(APPLIES_TEXT)).toBeInTheDocument()
  })

  test('error: the cause with its code, and Retry reads again', async () => {
    fetchMock.mockResolvedValueOnce(answer(500, { error: 'Failed to read the Tradecraft settings', code: 'P1001' }))
    renderDialog()
    expect(await screen.findByText(/Couldn't load your ingestion settings.*P1001.*HTTP 500/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
    fetchMock.mockResolvedValueOnce(answer(200, { v2Enabled: true, ingestion: VIEW }))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText(APPLIES_TEXT)).toBeInTheDocument()
  })

  test('denied: a 403 says the account cannot change them, with no form', async () => {
    fetchMock.mockResolvedValueOnce(answer(403, { error: 'Forbidden', code: 'own_account_only' }))
    renderDialog()
    expect(await screen.findByText(/You cannot change these settings: .*own_account_only/)).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Ingestion stages' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalled()
  })

  test('off: 2.0 turned off meanwhile (the switch read false, or the section answered 404)', async () => {
    fetchMock.mockResolvedValueOnce(answer(200, { v2Enabled: false }))
    renderDialog()
    expect(await screen.findByText(/Tradecraft 2.0 is off for this account/)).toBeInTheDocument()
    cleanup()
    fetchMock.mockResolvedValueOnce(answer(404, { error: 'Tradecraft 2.0 is off for this account', code: 'tradecraft_v2_off' }))
    renderDialog()
    expect(await screen.findByText(/turn it on to configure ingestion/)).toBeInTheDocument()
  })
})
