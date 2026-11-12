/**
 * useCan (step 3.12, UI-01): a screen asks whether the signed-in person may do something, and the
 * answer is what /api/auth/me said, the set can() decides with. Nothing is held while the session
 * loads, when the server could not resolve the set, or with no AuthProvider above the component.
 * After an act-as switch the provider reads the session again (refresh), so the answer follows.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, act } from '@testing-library/react'
import { AuthProvider, useAuth } from '@/providers/AuthProvider'
import type { PermissionId } from '@/lib/authz/permissions'
import { useCan, useRbacFlags } from './useCan'

const FLAGS = { sharedToolsCompat: false, identity: true, permissions: true, sharing: false, sharingWrite: false, governance: false }
const me = (capabilities: PermissionId[] | null, over: Record<string, unknown> = {}) =>
  new Response(JSON.stringify({ id: 'u1', name: 'U', email: 'u@e2e.local', role: 'admin', capabilities, flags: FLAGS, ...over }), { status: 200 })

function Probe({ permission, projectId }: { permission: PermissionId; projectId?: string }) {
  const allowed = useCan(permission, projectId)
  const flags = useRbacFlags()
  const { isLoading, refresh } = useAuth()
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="can">{String(allowed)}</span>
      <span data-testid="flags">{flags ? JSON.stringify(flags) : 'none'}</span>
      <button onClick={() => void refresh()}>refresh</button>
    </div>
  )
}

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function mount(permission: PermissionId, projectId?: string) {
  render(<AuthProvider><Probe permission={permission} projectId={projectId} /></AuthProvider>)
  await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
}

describe('useCan', () => {
  test('useCan true for a permission /api/auth/me lists, false for one it does not', async () => {
    fetchMock.mockResolvedValue(me(['users:read', 'platform:plugins']))
    await mount('users:read')
    expect(screen.getByTestId('can').textContent).toBe('true')
    cleanup()
    fetchMock.mockResolvedValue(me(['users:read', 'platform:plugins']))
    await mount('users:delete')
    expect(screen.getByTestId('can').textContent).toBe('false')
  })

  test('the project argument changes no answer yet (owner-only access; step 4.11 adds the level)', async () => {
    fetchMock.mockResolvedValue(me(['recon:scan']))
    await mount('recon:scan', 'P1')
    expect(screen.getByTestId('can').textContent).toBe('true')
  })

  test('false while the session loads, for a signed-out browser, and when the server sent null', async () => {
    let answer: (r: Response) => void = () => {}
    fetchMock.mockReturnValue(new Promise<Response>((r) => { answer = r }))
    render(<AuthProvider><Probe permission="users:read" /></AuthProvider>)
    expect(screen.getByTestId('can').textContent).toBe('false')
    await act(async () => answer(me(null)))
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
    expect(screen.getByTestId('can').textContent).toBe('false')
    cleanup()
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }))
    await mount('users:read')
    expect(screen.getByTestId('can').textContent).toBe('false')
  })

  test('the login answer, which carries no capabilities, holds nothing until the session is read (old shape)', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ id: 'u1', name: 'U', email: 'u@e2e.local', role: 'admin' }), { status: 200 }))
    await mount('users:read')
    expect(screen.getByTestId('can').textContent).toBe('false')
  })

  test('outside an AuthProvider: false, and no throw', () => {
    render(<ProbeAlone />)
    expect(screen.getByTestId('alone').textContent).toBe('false|none')
  })

  test('refresh reads the session again: after an act-as switch the answer follows the server', async () => {
    fetchMock.mockResolvedValueOnce(me(['users:read', 'recon:scan']))
    await mount('recon:scan')
    expect(screen.getByTestId('can').textContent).toBe('true')
    fetchMock.mockResolvedValueOnce(me(['users:read']))
    await act(async () => screen.getByRole('button', { name: 'refresh' }).click())
    await waitFor(() => expect(screen.getByTestId('can').textContent).toBe('false'))
    expect(fetchMock).toHaveBeenLastCalledWith('/api/auth/me', { cache: 'no-store' })
  })

  test('a failed refresh keeps what was shown', async () => {
    fetchMock.mockResolvedValueOnce(me(['recon:scan']))
    await mount('recon:scan')
    fetchMock.mockResolvedValueOnce(new Response('down', { status: 503 }))
    await act(async () => screen.getByRole('button', { name: 'refresh' }).click())
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    await act(async () => screen.getByRole('button', { name: 'refresh' }).click())
    expect(screen.getByTestId('can').textContent).toBe('true')
  })
})

describe('useRbacFlags', () => {
  test('the switch states /api/auth/me answered', async () => {
    fetchMock.mockResolvedValue(me([]))
    await mount('users:read')
    expect(JSON.parse(screen.getByTestId('flags').textContent!)).toEqual(FLAGS)
  })
})

describe('login', () => {
  test('a sign-in through the provider reads the session for what the person may use', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }))
    render(<AuthProvider><LoginProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('can').textContent).toBe('false'))
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: 'u1', name: 'U', email: 'u@e2e.local', role: 'admin' }), { status: 200 }))
    fetchMock.mockResolvedValueOnce(me(['users:read']))
    await act(async () => screen.getByRole('button', { name: 'sign in' }).click())
    await waitFor(() => expect(screen.getByTestId('can').textContent).toBe('true'))
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual(['/api/auth/me', '/api/auth/login', '/api/auth/me'])
  })
})

function ProbeAlone() {
  const allowed = useCan('users:read')
  const flags = useRbacFlags()
  return <span data-testid="alone">{`${allowed}|${flags ? 'flags' : 'none'}`}</span>
}

function LoginProbe() {
  const allowed = useCan('users:read')
  const { login } = useAuth()
  return (
    <div>
      <span data-testid="can">{String(allowed)}</span>
      <button onClick={() => void login('u@e2e.local', 'pw')}>sign in</button>
    </div>
  )
}
