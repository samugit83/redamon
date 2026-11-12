/**
 * Acting as another account changes what the person may use (/api/auth/me answers the set can()
 * decides with: under act-as, member permissions both people hold). So ProjectProvider reads the
 * session again (AuthProvider `refresh`) whenever it sets or clears the act-as cookie, and only an
 * account holding users:impersonate switches at all (step 3.12).
 *
 * Run: npx vitest run --no-file-parallelism src/providers/ProjectProvider.refresh.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'

const h = vi.hoisted(() => {
  const order: string[] = []
  return {
    order,
    canSwitch: true,
    actAsOk: true,
    // One object across renders, as Next's hook gives: the project load depends on it.
    search: new URLSearchParams(''),
    // One object across renders, as in the app.
    auth: { user: { id: 'admin' }, isLoading: false, refresh: vi.fn(async () => { order.push('refresh') }) },
  }
})
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => h.auth }))
vi.mock('@/hooks/useCan', () => ({ useCan: () => h.canSwitch, useRbacFlags: () => null }))
vi.mock('next/navigation', () => ({
  useSearchParams: () => h.search,
  useRouter: () => ({ replace: vi.fn() }),
  usePathname: () => '/graph',
}))

import { ProjectProvider, useProject } from './ProjectProvider'

function Consumer() {
  const { userId, setUserId } = useProject()
  return (
    <div>
      <span data-testid="userId">{userId ?? 'null'}</span>
      <button onClick={() => void setUserId('userX')}>switch</button>
      <button onClick={() => void setUserId('admin')}>back</button>
    </div>
  )
}

beforeEach(() => {
  localStorage.clear()
  h.order.length = 0
  h.canSwitch = true
  h.actAsOk = true
  h.auth.refresh.mockClear()
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
    const u = String(url)
    h.order.push(`${opts?.method ?? 'GET'} ${u}`)
    const ok = !(u.includes('/api/auth/act-as') && opts?.method === 'POST' && !h.actAsOk)
    return { ok, status: ok ? 200 : 404, json: async () => ({ id: 'P1' }), text: async () => '{"error":"Not found"}' } as unknown as Response
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

async function mount() {
  render(<ProjectProvider><Consumer /></ProjectProvider>)
  await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
}

describe('ProjectProvider reads the session again on an act-as change', () => {
  test('after the cookie is set, and after it is cleared', async () => {
    await mount()
    h.order.length = 0
    fireEvent.click(screen.getByText('switch'))
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('userX'))
    await waitFor(() => expect(h.order).toEqual(['POST /api/auth/act-as', 'refresh']))
    h.order.length = 0
    fireEvent.click(screen.getByText('back'))
    await waitFor(() => expect(h.order).toEqual(['DELETE /api/auth/act-as', 'refresh']))
  })

  test('a refused switch clears the cookie and reads the session again: the own set', async () => {
    await mount()
    h.actAsOk = false
    h.order.length = 0
    fireEvent.click(screen.getByText('switch'))
    await waitFor(() => expect(h.order).toEqual(['POST /api/auth/act-as', 'DELETE /api/auth/act-as', 'refresh']))
    expect(screen.getByTestId('userId').textContent).toBe('admin')
  })

  test('a saved target restored at load: the session is read again before any data loads', async () => {
    localStorage.setItem('redamon-current-user', 'userX')
    localStorage.setItem('redamon-current-project', 'P1')
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(h.order).toContain('GET /api/projects/P1'))
    expect(h.order).toEqual(['POST /api/auth/act-as', 'refresh', 'GET /api/projects/P1'])
  })

  test('without users:impersonate: no act-as call and nothing read again, whatever is saved', async () => {
    h.canSwitch = false
    localStorage.setItem('redamon-current-user', 'userX')
    await mount()
    fireEvent.click(screen.getByText('switch'))
    await new Promise((r) => setTimeout(r, 20))
    expect(screen.getByTestId('userId').textContent).toBe('admin')
    expect(h.order.filter((c) => c !== 'GET /api/projects/P1')).toEqual([])
    expect(h.auth.refresh).not.toHaveBeenCalled()
  })
})
