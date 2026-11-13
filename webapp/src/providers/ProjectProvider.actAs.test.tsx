/**
 * ProjectProvider with RBAC_PERMISSIONS_ENABLED on (step 3.14; IM-02, IM-04): the server holds the
 * impersonation, with a time limit the browser must not outlive.
 *
 * - no auto restore: a target remembered in localStorage is dropped, never re-posted; the effective
 *   user is whom /api/auth/me says the admin acts as (`actingAs`), else the admin;
 * - switching to someone else opens the act-as dialog (reason, duration, password) and posts what it
 *   collected; a refusal stays in the dialog; switching back to oneself stops it (DELETE); each switch
 *   reads the session again and forgets the previous account's project.
 *
 * With the switch off ProjectProvider.test.tsx and ProjectProvider.stepUp.test.tsx hold, unchanged.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'

type User = { id: string; actingAs?: { id: string } | null; impersonation?: { maxMinutes: number; reasonRequired: boolean } | null }
let mockAuth: { user: User | null; isLoading: boolean; refresh: () => Promise<void> }
const refresh = vi.fn(async () => {})

vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => ({ permissions: true }) }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => mockAuth }))
vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(''),
  useRouter: () => ({ replace: vi.fn() }),
  usePathname: () => '/graph',
}))

import { ProjectProvider, useProject } from './ProjectProvider'

let outcome: unknown = 'pending'
function Consumer() {
  const { userId, setUserId } = useProject()
  return (
    <div>
      <span data-testid="userId">{userId ?? 'null'}</span>
      <button onClick={async () => { outcome = await setUserId('member-1', { target: { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', accountType: 'member' } }) }}>switch</button>
      <button onClick={() => { void setUserId('admin-1') }}>self</button>
      <button onClick={() => { void setUserId('member-1') }}>unnamed</button>
    </div>
  )
}

type Call = { url: string; method: string; body: string }
let calls: Call[]
let answer: { ok: boolean; status: number; body: Record<string, unknown> }

beforeEach(() => {
  calls = []
  outcome = 'pending'
  refresh.mockClear()
  localStorage.clear()
  mockAuth = { user: { id: 'admin-1', actingAs: null, impersonation: { maxMinutes: 120, reasonRequired: true } }, isLoading: false, refresh }
  answer = { ok: true, status: 200, body: { actingAs: 'member-1' } }
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
    calls.push({ url: String(url), method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
    return {
      ok: answer.ok, status: answer.status, statusText: '', headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => answer.body, text: async () => JSON.stringify(answer.body), clone() { return this },
    } as unknown as Response
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const actAsCalls = () => calls.filter((c) => c.url === '/api/auth/act-as')

describe('no auto restore (IM-02)', () => {
  test('a remembered target is dropped, nothing is posted, the admin stays themselves', async () => {
    localStorage.setItem('redamon-current-user', 'member-1')
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId')).toHaveTextContent('admin-1'))
    expect(actAsCalls()).toEqual([])
    expect(localStorage.getItem('redamon-current-user')).toBeNull()
  })

  test('the server says whom the admin acts as: that is the effective user, nothing is posted or cleared', async () => {
    mockAuth.user = { ...mockAuth.user!, actingAs: { id: 'member-1' } }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId')).toHaveTextContent('member-1'))
    expect(actAsCalls()).toEqual([])
  })
})

describe('switching opens the act-as dialog', () => {
  test('reason, duration and password are posted; the session is read again', async () => {
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    fireEvent.click(screen.getByText('switch'))
    expect(await screen.findByRole('dialog', { name: 'Act as another account' })).toBeInTheDocument()
    expect(screen.getByText('Reason (required)')).toBeInTheDocument()
    expect((screen.getByLabelText('For how long') as HTMLSelectElement).value).toBe('60')
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: 'ticket #42' } })
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: 'Act as Marco' }))
    await waitFor(() => expect(screen.getByTestId('userId')).toHaveTextContent('member-1'))
    expect(actAsCalls()).toEqual([{
      url: '/api/auth/act-as', method: 'POST',
      body: JSON.stringify({ targetUserId: 'member-1', stepUpPassword: 'pw', reason: 'ticket #42', durationMinutes: 60 }),
    }])
    expect(refresh).toHaveBeenCalled()
    await waitFor(() => expect(outcome).toBeNull())
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('a refusal stays in the dialog and changes nothing', async () => {
    answer = { ok: false, status: 403, body: { error: 'Password is incorrect', code: 'step_up_failed' } }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    fireEvent.click(screen.getByText('switch'))
    fireEvent.change(await screen.findByLabelText(/^Reason/), { target: { value: 'x' } })
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: 'Act as Marco' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Password is incorrect')
    expect(screen.getByTestId('userId')).toHaveTextContent('admin-1')
  })

  test('cancelled: nothing posted, the caller learns nothing went wrong', async () => {
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    fireEvent.click(screen.getByText('switch'))
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(outcome).toBeNull())
    expect(actAsCalls()).toEqual([])
    expect(screen.getByTestId('userId')).toHaveTextContent('admin-1')
  })

  test('a caller that does not name the account: the dialog says "this account", never its id (3.16c)', async () => {
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    fireEvent.click(screen.getByText('unnamed'))
    const dialog = await screen.findByRole('dialog', { name: 'Act as another account' })
    expect(dialog).toHaveTextContent('You will see and do what this account sees and does')
    expect(dialog).not.toHaveTextContent('member-1')
    expect(screen.queryByTestId('identity-label')).toBeNull()
    expect(screen.getByRole('button', { name: 'Act as this account' })).toBeInTheDocument()
  })

  test('back to oneself stops it on the server and reads the session again', async () => {
    mockAuth.user = { ...mockAuth.user!, actingAs: { id: 'member-1' } }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId')).toHaveTextContent('member-1'))
    fireEvent.click(screen.getByText('self'))
    await waitFor(() => expect(actAsCalls()).toEqual([{ url: '/api/auth/act-as', method: 'DELETE', body: '' }]))
    await waitFor(() => expect(refresh).toHaveBeenCalled())
  })
})
