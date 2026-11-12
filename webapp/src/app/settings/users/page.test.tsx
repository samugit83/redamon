/**
 * Settings > Users: a list that failed to load says why, instead of
 * "No users found" (which reads as an empty database).
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'

const usersState = vi.hoisted(() => ({
  value: { data: undefined as unknown, isLoading: false, error: null as Error | null },
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(''),
}))
// The page's permissions (hooks/useCan.ts): an admin holding every user permission.
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'admin-1' }, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => usersState.value,
  useCreateUser: () => ({ mutateAsync: vi.fn() }),
  useDeleteUser: () => ({ mutateAsync: vi.fn() }),
  useChangePassword: () => ({ mutateAsync: vi.fn() }),
}))

import UsersPage from './page'

afterEach(() => cleanup())

describe('Users list', () => {
  test('a failed load shows the cause, not "No users found"', () => {
    usersState.value = {
      data: undefined, isLoading: false,
      error: new ApiError({ reason: 'Failed to fetch users', status: 500, code: 'P1001' }),
    }
    render(<UsersPage />)
    expect(screen.getByRole('alert').textContent).toBe('Failed to fetch users (P1001 · HTTP 500)')
    expect(screen.queryByText('No users found')).toBeNull()
  })

  test('an empty list that did load is still "No users found"', () => {
    usersState.value = { data: [], isLoading: false, error: null }
    render(<UsersPage />)
    expect(screen.getByText('No users found')).toBeInTheDocument()
  })
})
