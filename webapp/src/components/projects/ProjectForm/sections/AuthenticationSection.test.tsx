/**
 * The auth profile section names why a load, save, toggle or clear failed. A
 * failed load used to leave the section showing type "none" as if no profile
 * were set, a clear failed silently, and a toggle hid the server's own reason.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/sections/AuthenticationSection.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const alertError = vi.fn()
vi.mock('@/components/ui', async (orig) => ({
  ...(await orig<typeof import('@/components/ui')>()),
  useAlertModal: () => ({ alertError, alert: vi.fn() }),
}))
vi.mock('@/components/traffic/RecordingModal', () => ({ RecordingModal: () => null }))

import { AuthenticationSection } from './AuthenticationSection'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const PROFILE = {
  authType: 'cookie', authHeaderName: '', hasValue: true, source: 'manual', status: 'unknown',
  scopeHosts: [], reconEnabled: true, agentEnabled: true, extraHeaderNames: [],
}

let put: (body: Record<string, unknown>) => Response

beforeEach(() => {
  vi.clearAllMocks()
  put = () => json(200, { authProfile: PROFILE })
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) =>
    init?.method === 'PUT' ? put(JSON.parse(String(init.body))) : json(200, { authProfile: PROFILE })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function open() {
  render(<AuthenticationSection data={{} as never} updateField={vi.fn() as never} projectId="p1" mode="edit" />)
  fireEvent.click(screen.getByText('Authenticated Session'))
}

test('a failed load says so instead of showing an empty profile', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: 'Failed to load auth profile', code: 'P1001' })))
  open()
  expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load auth profile (P1001 · HTTP 500)')
})

describe('writes', () => {
  test('a refused toggle shows the server\'s reason and rolls back', async () => {
    put = () => json(400, { error: 'agentEnabled must be a boolean' })
    open()
    const toggle = await screen.findByRole('switch', { name: 'Apply to agent' })
    await waitFor(() => expect(toggle).toBeEnabled())
    fireEvent.click(toggle)
    await waitFor(() => expect(alertError).toHaveBeenCalledWith('agentEnabled must be a boolean (HTTP 400)'))
    expect(toggle).toHaveAttribute('aria-checked', 'true')
  })

  test('the switches wait for the first load, so its answer cannot overwrite a click', async () => {
    let answer: (r: Response) => void = () => {}
    vi.stubGlobal('fetch', vi.fn((_url: string, init?: RequestInit) =>
      init?.method === 'PUT' ? Promise.resolve(put({})) : new Promise<Response>(r => { answer = r })))
    open()
    const toggle = screen.getByRole('switch', { name: 'Apply to agent' })
    expect(toggle).toBeDisabled()
    fireEvent.click(toggle)
    answer(json(200, { authProfile: { ...PROFILE, agentEnabled: false } }))
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(toggle).toHaveAttribute('aria-checked', 'false')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  test('a failed clear is alerted, not swallowed', async () => {
    put = () => json(500, { error: 'Failed to save auth profile', code: 'P2024' })
    open()
    fireEvent.click(await screen.findByText('Clear the stored value'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith('Failed to save auth profile (P2024 · HTTP 500)'))
  })

  test('a save that gets no answer says network_error', async () => {
    open()
    await screen.findByText('Clear the stored value')
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    fireEvent.change(screen.getByPlaceholderText(/a value is set/), { target: { value: 'sid=new' } })
    fireEvent.click(screen.getByRole('button', { name: /Save/ }))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith('Failed to save the auth profile (network_error)'))
  })
})
