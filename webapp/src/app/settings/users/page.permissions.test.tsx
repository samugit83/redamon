/**
 * Settings > Users follows the permissions (step 3.12, UI-01, UI-12): the page is the directory's
 * (users:read), creating and inviting users:create's, deleting users:delete's. A list the server
 * refused for a permission shows that permission and "ask an administrator" (ForbiddenNotice).
 *
 * Run: npx vitest run --no-file-parallelism src/app/settings/users/page.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'
import { PERMISSIONS } from '@/lib/authz/permissions'

const h = vi.hoisted(() => ({
  granted: new Set<string>(),
  push: vi.fn(),
  users: { data: undefined as unknown, isLoading: false, error: null as Error | null },
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: h.push, replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(''),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin' }, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => h.users,
  useCreateUser: () => ({ mutateAsync: vi.fn() }),
  useDeleteUser: () => ({ mutateAsync: vi.fn() }),
  useChangePassword: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/components/admin/LegacyAccessCard', () => ({ LegacyAccessCard: () => null }))
vi.mock('@/components/admin/WhatChangedCard', () => ({ WhatChangedCard: () => null }))

import UsersPage from './page'

const ROWS = [
  { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', status: 'active', hasPassword: true, createdAt: '', updatedAt: '', _count: { projects: 0 } },
  { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', role: 'standard', status: 'active', hasPassword: true, createdAt: '', updatedAt: '', _count: { projects: 1 } },
]

beforeEach(() => {
  h.granted = new Set(['users:read'])
  h.push.mockReset()
  h.users = { data: ROWS, isLoading: false, error: null }
})
afterEach(() => cleanup())

describe('the Users page', () => {
  test('reading the directory alone: the list, no Create User and no Delete', () => {
    render(<UsersPage />)
    expect(screen.getByText('marco@e2e.local')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create User' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull()
  })

  test('users:create shows Create User, users:delete shows Delete on another account', () => {
    h.granted = new Set(['users:read', 'users:create', 'users:delete'])
    render(<UsersPage />)
    expect(screen.getByRole('button', { name: 'Create User' })).toBeInTheDocument()
    // Nobody deletes their own account: one Delete, on Marco's row.
    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(1)
  })

  test('without users:read the page shows nothing and goes to the graph', async () => {
    h.granted = new Set(['users:create', 'users:delete'])
    const { container } = render(<UsersPage />)
    expect(container.textContent).toBe('')
    await waitFor(() => expect(h.push).toHaveBeenCalledWith('/graph'))
  })

  test('a list refused for a permission shows that permission and who can grant it', () => {
    h.users = {
      data: undefined, isLoading: false,
      error: new ApiError({
        reason: 'You do not hold the permission this action needs (users:read).', status: 403, code: 'forbidden',
        body: { error: 'You do not hold the permission this action needs (users:read).', code: 'forbidden', permission: 'users:read' },
      }),
    }
    render(<UsersPage />)
    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('users:read')
    expect(notice).toHaveTextContent(PERMISSIONS['users:read'].description)
    expect(notice).toHaveTextContent('Ask an administrator to grant it to you.')
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })
})
