/**
 * Settings > Users and the identity label (step 2.11, ID-31): with the identity switch on, the
 * dialogs that act on an account (Set Password, Delete) name it by its name, email and account
 * type (Root, Admin, Member), never by the display name alone. With the switch off: Phase 1's page.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  me: { id: 'admin-1' } as Record<string, unknown>,
  users: [] as unknown[],
}))

vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.search,
}))
// The page's permissions (hooks/useCan.ts): an admin holding every user permission.
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: h.me, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: h.users, isLoading: false, error: null, refetch: vi.fn() }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

import UsersPage from './page'

const row = (id: string, name: string, role: string) =>
  ({ id, name, email: `${id}@x.z`, role, status: 'active', hasPassword: true, _count: { projects: 0 } })

function as(identity: boolean, rootEmail = 'admin-1@x.z') {
  h.me = {
    id: 'admin-1',
    email: 'admin-1@x.z',
    ...(identity ? { accountType: rootEmail === 'admin-1@x.z' ? 'root' : 'admin' } : {}),
    rbac: {
      compat: false, legacyGrantsPending: 0,
      ...(identity ? { identity: true, root: { email: rootEmail, confirmed: true, chosenAt: null } } : {}),
    },
  }
}
const rowOf = (name: string) => within(screen.getByText(name).closest('tr') as HTMLElement)
const dialog = () => screen.getByRole('dialog')

beforeEach(() => {
  // Two accounts share a display name: only the email and the type tell them apart.
  h.users = [row('admin-1', 'Ada', 'admin'), row('admin-2', 'Marco', 'admin'), row('member-1', 'Marco R', 'standard')]
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('switch on: the dialogs name the account by email and type', () => {
  test('Set Password on a member: name, email, Member', () => {
    as(true)
    render(<AlertProvider><UsersPage /></AlertProvider>)
    fireEvent.click(rowOf('Marco R').getByRole('button', { name: 'Set Password' }))
    const label = within(dialog()).getByTestId('identity-label')
    expect(label).toHaveAttribute('aria-label', 'Marco R, member-1@x.z, Member')
  })

  test('Delete on a member: the same label in the confirmation', () => {
    as(true)
    render(<AlertProvider><UsersPage /></AlertProvider>)
    fireEvent.click(rowOf('Marco R').getByRole('button', { name: 'Delete' }))
    expect(within(dialog()).getByTestId('identity-label')).toHaveAttribute('aria-label', 'Marco R, member-1@x.z, Member')
  })

  test('the Root, seen by another admin, reads Root; another admin reads Admin', () => {
    as(true, 'admin-2@x.z')
    h.users = [row('admin-1', 'Ada', 'admin'), row('admin-2', 'Marco', 'admin')]
    render(<AlertProvider><UsersPage /></AlertProvider>)
    fireEvent.click(rowOf('Ada').getByRole('button', { name: 'Set Password' }))
    expect(within(dialog()).getByTestId('identity-label')).toHaveAttribute('aria-label', 'Ada, admin-1@x.z, Admin')
  })
})

describe('switch off: Phase 1 dialogs', () => {
  test('no identity label in Set Password or Delete', () => {
    as(false)
    render(<AlertProvider><UsersPage /></AlertProvider>)
    fireEvent.click(rowOf('Marco R').getByRole('button', { name: 'Set Password' }))
    expect(screen.queryByTestId('identity-label')).toBeNull()
  })
})
