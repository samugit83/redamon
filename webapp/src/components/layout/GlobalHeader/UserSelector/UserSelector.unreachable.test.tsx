/**
 * The session read got no answer even after its retries (the network or the server is down): the
 * header says so and offers Retry, which reloads the page and so reads everything again, instead of
 * a bare "No User". A session the server answered (a 5xx, a sign-out) shows as before.
 *
 * Run: npx vitest run --no-file-parallelism src/components/layout/GlobalHeader/UserSelector/UserSelector.unreachable.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { ApiError, toApiError } from '@/lib/apiError'

const state = vi.hoisted(() => ({ sessionError: null as unknown }))

vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: null, setUserId: vi.fn(), setCurrentProject: vi.fn(), userSwitchError: null }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: () => false, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: null, logout: vi.fn(), sessionError: state.sessionError }),
}))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: [] }) }))
vi.mock('@/context/NavigationGuardContext', () => ({
  useGuardedRouter: () => ({ push: vi.fn() }),
  useNavigationGuard: () => null,
}))

import { UserSelector } from './UserSelector'

const realLocation = window.location
let reload: ReturnType<typeof vi.fn>
beforeEach(() => {
  reload = vi.fn()
  Object.defineProperty(window, 'location', { configurable: true, value: { ...realLocation, reload } })
})
afterEach(() => {
  cleanup()
  state.sessionError = null
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
})

const renderSelector = () => render(<ToastProvider><UserSelector /></ToastProvider>)

describe('UserSelector when the session could not be read', () => {
  test.each([
    ['a network error', new TypeError('Failed to fetch')],
    ['an abort', new DOMException('The operation was aborted.', 'AbortError')],
  ])('no answer (%s): "Server unreachable · Retry" instead of "No User", and Retry reloads the page', (_what, failure) => {
    state.sessionError = toApiError(failure, 'Could not read your session')
    renderSelector()
    expect(screen.queryByText('No User')).toBeNull()
    const retry = screen.getByRole('button', { name: /Server unreachable · Retry/ })
    expect(retry.getAttribute('title')).toContain('Could not reach the server')
    fireEvent.click(retry)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  test.each([
    ['an answered 5xx', new ApiError({ reason: 'Internal server error', status: 500, code: 'P1001' })],
    ['a plain sign-out (no error)', null],
  ])('%s: "No User" as before, no Retry', (_what, error) => {
    state.sessionError = error
    renderSelector()
    expect(screen.getByText('No User')).toBeInTheDocument()
    expect(screen.queryByText(/Server unreachable/)).toBeNull()
    fireEvent.click(screen.getByTitle('User Menu'))
    expect(reload).not.toHaveBeenCalled()
  })
})
