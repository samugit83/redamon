/**
 * A switch to another admin carries the step-up password (ID-25). A refused
 * password leaves everything as it was, so the dialog can ask again: no new
 * effective user, no saved selection, no act-as reset, no toast.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import type { ApiError } from '@/lib/apiError'

// One object across renders, as in the app: the provider's effects depend on it.
const AUTH = vi.hoisted(() => ({ user: { id: 'admin' }, isLoading: false, canSwitchUser: true }))
// Whether the signed-in person may act as others (users:impersonate, hooks/useCan.ts).
vi.mock('@/hooks/useCan', () => ({ useCan: () => AUTH.canSwitchUser, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => AUTH }))
vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(''),
  useRouter: () => ({ replace: vi.fn() }),
  usePathname: () => '/graph',
}))

import { ProjectProvider, useProject } from './ProjectProvider'

type Call = { url: string; method: string; body: string }
let calls: Call[]
let actAsAnswer: () => Response
let result: ApiError | null | undefined

function Consumer() {
  const { userId, setUserId, userSwitchError } = useProject()
  return (
    <div>
      <span data-testid="userId">{userId ?? 'null'}</span>
      <span data-testid="switchError">{userSwitchError?.message ?? ''}</span>
      <button data-testid="switch" onClick={async () => { result = await setUserId('admin2', { stepUpPassword: 'my-own-passphrase' }) }}>switch</button>
    </div>
  )
}

beforeEach(() => {
  calls = []
  result = undefined
  localStorage.clear()
  actAsAnswer = () => new Response(JSON.stringify({ actingAs: 'admin2' }), { status: 200 })
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
    const u = String(url)
    const method = init?.method ?? 'GET'
    calls.push({ url: u, method, body: init?.body ? String(init.body) : '' })
    if (u.includes('/api/auth/act-as') && method === 'POST') return actAsAnswer()
    return new Response(JSON.stringify({}), { status: 200 })
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

async function mountAndSwitch() {
  render(<ProjectProvider><Consumer /></ProjectProvider>)
  await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
  // The mount-time reconcile clears any act-as cookie first.
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE')).toBe(true))
  const before = calls.length
  fireEvent.click(screen.getByTestId('switch'))
  await waitFor(() => expect(result).not.toBeUndefined())
  return calls.slice(before)
}

describe('setUserId with a step-up password', () => {
  test('the password goes in the act-as body; success switches and resolves null', async () => {
    const sent = await mountAndSwitch()
    const post = sent.find(c => c.method === 'POST')!
    expect(JSON.parse(post.body)).toEqual({ targetUserId: 'admin2', stepUpPassword: 'my-own-passphrase' })
    expect(result).toBeNull()
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin2'))
    expect(localStorage.getItem('redamon-current-user')).toBe('admin2')
  })

  test('a refused password resolves the error and changes nothing', async () => {
    actAsAnswer = () => new Response(JSON.stringify({ error: 'Password is incorrect', code: 'step_up_failed' }), { status: 403 })
    const sent = await mountAndSwitch()
    expect(result?.message).toBe('Password is incorrect (step_up_failed · HTTP 403)')
    expect(sent.filter(c => c.method === 'DELETE')).toHaveLength(0)
    expect(screen.getByTestId('userId').textContent).toBe('admin')
    expect(screen.getByTestId('switchError').textContent).toBe('')
    expect(localStorage.getItem('redamon-current-user')).toBeNull()
  })

  test('no answer resolves a network error and changes nothing', async () => {
    actAsAnswer = () => { throw new TypeError('Failed to fetch') }
    await mountAndSwitch()
    expect(result?.message).toBe('Could not switch user (network_error)')
    expect(screen.getByTestId('userId').textContent).toBe('admin')
    expect(screen.getByTestId('switchError').textContent).toBe('')
  })
})
