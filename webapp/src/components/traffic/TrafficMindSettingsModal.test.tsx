/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

const toastSuccess = vi.fn()
const toastError = vi.fn()
const toastWarning = vi.fn()
const confirmMock = vi.fn<() => Promise<boolean>>()

// Lightweight stand-ins for the shared UI kit so the test exercises the modal's
// save/dirty logic, not the design system.
vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: toastSuccess, error: toastError, warning: toastWarning }),
  useAlertModal: () => ({ confirm: confirmMock }),
  Toggle: ({ checked, onChange, 'aria-label': label }: { checked: boolean; onChange: (v: boolean) => void; 'aria-label': string }) => (
    <input type="checkbox" aria-label={label} checked={checked} onChange={(e) => onChange(e.target.checked)} />
  ),
  Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/Modal/Modal', () => ({
  Modal: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) => (isOpen ? <div>{children}</div> : null),
}))
vi.mock('@/components/traffic/TrafficMindProjectMatrix', () => ({
  TrafficMindProjectMatrix: () => <div data-testid="matrix" />,
}))

import { TrafficMindSettingsModal } from './TrafficMindSettingsModal'

// A stateful fake of /api/users/[id]/settings: GET returns current server state,
// PUT merges the patch and echoes it back (like the real route).
function mockSettingsApi() {
  const serverState: Record<string, unknown> = {}
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((async (_url: string, init?: RequestInit) => {
    if (!init || (init.method ?? 'GET') === 'GET') {
      return { ok: true, json: async () => ({ ...serverState }) } as Response
    }
    Object.assign(serverState, JSON.parse(init.body as string))
    return { ok: true, json: async () => ({ ...serverState }) } as Response
  }) as typeof fetch)
  const puts = () => fetchMock.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')
  const lastPutBody = () => JSON.parse((puts().at(-1)![1] as RequestInit).body as string)
  return { fetchMock, puts, lastPutBody }
}

async function renderOpen() {
  const onClose = vi.fn()
  render(<TrafficMindSettingsModal isOpen onClose={onClose} userId="user-1" />)
  // Initial GET load settles → Apply button present.
  await screen.findByRole('button', { name: 'Apply' })
  return { onClose }
}

describe('TrafficMindSettingsModal — batched Apply', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
    toastWarning.mockReset()
    confirmMock.mockReset()
  })
  afterEach(() => cleanup())

  test('starts clean: Apply disabled, no Revert, no PUT on load', async () => {
    const api = mockSettingsApi()
    await renderOpen()
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Revert' })).toBeNull()
    expect(screen.getByText('All changes saved')).toBeInTheDocument()
    expect(api.puts()).toHaveLength(0)
  })

  test('editing a number field marks dirty but does NOT persist until Apply', async () => {
    const api = mockSettingsApi()
    await renderOpen()
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled())
    expect(screen.getByText('● Unsaved changes')).toBeInTheDocument()
    expect(api.puts()).toHaveLength(0) // nothing persisted yet
  })

  test('toggling a switch does NOT persist until Apply', async () => {
    const api = mockSettingsApi()
    await renderOpen()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Store bodies' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled())
    expect(api.puts()).toHaveLength(0)
  })

  test('Apply sends ONE PUT with only the changed fields (one respawn for many edits)', async () => {
    const api = mockSettingsApi()
    await renderOpen()
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Store bodies' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Passive detections' }))

    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(api.puts()).toHaveLength(1))
    expect(api.lastPutBody()).toEqual({
      captureProxyPort: 9000,
      captureProxyStoreBodies: false,
      captureProxyPassiveDetect: false,
    })
    await waitFor(() => expect(toastSuccess).toHaveBeenCalled())
  })

  test('after a successful Apply the form is clean again', async () => {
    mockSettingsApi()
    await renderOpen()
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled())
    expect(screen.getByText('All changes saved')).toBeInTheDocument()
  })

  test('Revert drops pending edits without any PUT', async () => {
    const api = mockSettingsApi()
    await renderOpen()
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Revert' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled())
    expect(screen.getByDisplayValue('8888')).toBeInTheDocument()
    expect(api.puts()).toHaveLength(0)
  })

  test('master toggle is batched: off + Apply sends captureProxyEnabled:false once', async () => {
    const api = mockSettingsApi()
    await renderOpen()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable TrafficMind capture' }))
    // Sub-sections collapse; still no PUT until Apply.
    expect(api.puts()).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(api.puts()).toHaveLength(1))
    expect(api.lastPutBody()).toEqual({ captureProxyEnabled: false })
  })

  test('closing with unsaved edits asks to confirm and respects a cancel', async () => {
    mockSettingsApi()
    const { onClose } = await renderOpen()
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })

    confirmMock.mockResolvedValueOnce(false) // user cancels the discard
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(confirmMock).toHaveBeenCalledTimes(1))
    expect(onClose).not.toHaveBeenCalled()

    confirmMock.mockResolvedValueOnce(true) // user confirms discard
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
  })

  test('closing a clean form does not prompt', async () => {
    mockSettingsApi()
    const { onClose } = await renderOpen()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
    expect(confirmMock).not.toHaveBeenCalled()
  })

  test('a failed Apply keeps the edits and warns', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((async (_url: string, init?: RequestInit) => {
      if (!init || (init.method ?? 'GET') === 'GET') return { ok: true, json: async () => ({}) } as Response
      return { ok: false, json: async () => ({}) } as Response // PUT rejected
    }) as typeof fetch)
    await renderOpen()
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(toastError).toHaveBeenCalled())
    // Edit survives → still dirty, value unchanged.
    expect(screen.getByDisplayValue('9000')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled()
    fetchMock.mockRestore()
  })
})

/** GET answers `get`; every PUT answers `put`. Both are {status, body}. */
function mockAnswers(get: () => { status: number; body: unknown }, put: () => { status: number; body: unknown } | Error) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((async (_url: string, init?: RequestInit) => {
    const a = !init || (init.method ?? 'GET') === 'GET' ? get() : put()
    if (a instanceof Error) throw a
    return new Response(JSON.stringify(a.body), { status: a.status })
  }) as typeof fetch)
}

async function editPortAndApply() {
  await screen.findByRole('button', { name: 'Apply' })
  fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
}

describe('TrafficMindSettingsModal — failures say their cause', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
    toastWarning.mockReset()
  })
  afterEach(() => cleanup())

  test('a failed load says so and keeps Apply off, so the defaults are never sent as saved values', async () => {
    let getStatus = 500
    const fetchMock = mockAnswers(
      () => getStatus === 200
        ? { status: 200, body: {} }
        : { status: 500, body: { error: 'Failed to fetch user settings', code: 'P1001' } },
      () => ({ status: 200, body: {} }),
    )
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    expect((await screen.findByRole('alert')).textContent)
      .toContain("Couldn't load the TrafficMind settings (P1001 · HTTP 500). Apply is off until they load.")
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled()

    getStatus = 200
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
    fireEvent.change(screen.getByDisplayValue('8888'), { target: { value: '9000' } })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled())
    expect(fetchMock.mock.calls.some((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')).toBe(false)
  })

  test('a server failure shows its code and status, not "admin-only"', async () => {
    mockAnswers(() => ({ status: 200, body: {} }),
      () => ({ status: 500, body: { error: 'Failed to update user settings', code: 'P2024' } }))
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    await editPortAndApply()
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Not saved - Failed to update user settings (P2024 · HTTP 500)'))
    expect(toastSuccess).not.toHaveBeenCalled()
  })

  test('a refused value shows the route\'s own reason', async () => {
    mockAnswers(() => ({ status: 200, body: {} }),
      () => ({ status: 400, body: { error: 'Unknown feature model id' } }))
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    await editPortAndApply()
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Not saved - Unknown feature model id (HTTP 400)'))
  })

  test('no answer at all reads as a network failure', async () => {
    mockAnswers(() => ({ status: 200, body: {} }), () => new TypeError('Failed to fetch'))
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    await editPortAndApply()
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Not saved - the request failed (network_error)'))
  })

  test('saved but the proxy did not restart: success plus a warning with the cause', async () => {
    mockAnswers(() => ({ status: 200, body: {} }), () => ({
      status: 200,
      body: {
        captureProxyPort: 9000,
        warnings: [{
          service: 'orchestrator', message: 'The capture proxy was not started',
          code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
        }],
      },
    }))
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    await editPortAndApply()
    await waitFor(() => expect(toastWarning).toHaveBeenCalledWith(
      'The capture proxy was not started (orchestrator_unreachable · ECONNREFUSED)', 'Saved, but not applied'))
    expect(toastSuccess).toHaveBeenCalledWith('TrafficMind settings applied')
  })

  test('fields the route ignored (not an admin) are not reported as applied', async () => {
    mockAnswers(() => ({ status: 200, body: {} }),
      () => ({ status: 200, body: { ignoredFields: ['captureProxyPort'] } }))
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    await editPortAndApply()
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Not saved - TrafficMind settings are admin-only'))
    expect(toastSuccess).not.toHaveBeenCalled()
  })
})

// Step 2.4 (F-15): with the identity switch on the user GET points at the instance
// settings, and the modal loads and saves them there, under the signed-in admin.
describe('TrafficMindSettingsModal — instance settings (identity switch on)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
    toastWarning.mockReset()
  })
  afterEach(() => cleanup())

  function mockInstanceApi(putAnswer: () => Response = () => new Response(JSON.stringify({ captureProxyPort: 9000 }), { status: 200 })) {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((async (url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method === 'GET' && url === '/api/users/user-1/settings') {
        return new Response(JSON.stringify({ captureProxyPort: 1, canManageTunnels: false, sharedSettingsAt: 'instance' }), { status: 200 })
      }
      if (method === 'GET' && url === '/api/admin/instance-settings') {
        return new Response(JSON.stringify({ captureProxyPort: 8888, canManageCapture: true }), { status: 200 })
      }
      if (method === 'PUT' && url === '/api/admin/instance-settings') return putAnswer()
      return new Response('{}', { status: 500 })
    }) as typeof fetch)
    return fetchMock
  }

  test('TrafficMind save while acting writes the singleton: it loads and saves the instance settings', async () => {
    const fetchMock = mockInstanceApi()
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    // The instance value, not the member row's.
    fireEvent.change(await screen.findByDisplayValue('8888'), { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith('TrafficMind settings applied'))
    const puts = fetchMock.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')
    expect(puts.map((c) => c[0])).toEqual(['/api/admin/instance-settings'])
    expect(JSON.parse((puts[0][1] as RequestInit).body as string)).toEqual({ captureProxyPort: 9000 })
  })

  test('a refusal of the instance route is shown with its reason, nothing reads as applied', async () => {
    mockInstanceApi(() => new Response(JSON.stringify({
      error: 'Only an administrator changes the TrafficMind settings.', code: 'forbidden',
    }), { status: 403 }))
    render(<TrafficMindSettingsModal isOpen onClose={vi.fn()} userId="user-1" />)
    fireEvent.change(await screen.findByDisplayValue('8888'), { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(toastError).toHaveBeenCalledWith(expect.stringContaining('Only an administrator changes the TrafficMind settings.')))
    expect(toastSuccess).not.toHaveBeenCalled()
  })
})
