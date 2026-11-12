/**
 * Settings > Users, the columns and the actions per row (step 2.12, ID-27, ID-12, UI-04, DV-06).
 * Every row shows its status (Active, Invited, Disabled), its owned projects and its last sign-in
 * ("Not recorded" when it has none: sign-ins are recorded only since the identity schema),
 * whatever the identity switch. With the switch on the role column is
 * the account type (Root, Admin, Member; an unconfirmed Root says so) and a password that must
 * change is shown; off it is Phase 1's role column, and the must-change flag means nothing. The row
 * actions follow the hierarchy with the switch on (Root acts on admins and members, an admin on
 * members only, nobody on Root) and Phase 1's rules off. The list has loading, error (with Retry)
 * and empty states, and a non-admin is sent away. Creating a passwordless account stays available.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  router: { push: vi.fn(), replace: vi.fn() },
  me: { id: 'admin-1' } as Record<string, unknown>,
  isAdmin: true,
  list: { data: [] as unknown[] | undefined, isLoading: false, error: null as Error | null },
  refetch: vi.fn(),
  create: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.search,
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: h.me, isAdmin: h.isAdmin, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ ...h.list, refetch: h.refetch }),
  useCreateUser: () => ({ mutateAsync: h.create, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

import UsersPage from './page'

const LOGIN = '2026-11-01T10:00:00.000Z'

interface Row {
  id: string; name: string; email: string; role: string; status: string; hasPassword: boolean
  lastLoginAt: string | null; mustChangePassword?: boolean; _count: { projects: number }
}
const row = (id: string, name: string, role: string, over: Partial<Row> = {}): Row => ({
  id, name, email: `${id}@x.z`, role, status: 'active', hasPassword: true, lastLoginAt: null, _count: { projects: 0 }, ...over,
})

function rows(): Row[] {
  return [
    row('root-1', 'Rita', 'admin', { lastLoginAt: LOGIN }),
    row('admin-1', 'Ada', 'admin', { _count: { projects: 4 } }),
    row('admin-2', 'Pia', 'admin'),
    row('member-1', 'Marco', 'standard', { mustChangePassword: true, lastLoginAt: LOGIN }),
    row('member-2', 'Anna', 'standard', { status: 'disabled', hasPassword: false }),
    row('member-3', 'Nina', 'standard', { status: 'invited', hasPassword: false }),
  ]
}

type Viewer = 'admin-off' | 'admin-on' | 'unconfirmed-root-viewer' | 'root' | 'unconfirmed-root'
/** Who looks at the page. With the switch on Root is root-1 unless the viewer is Root itself (admin-1). */
function as(viewer: Viewer) {
  const identity = viewer !== 'admin-off'
  const viewerIsRoot = viewer === 'root' || viewer === 'unconfirmed-root-viewer'
  h.me = {
    id: 'admin-1',
    email: 'admin-1@x.z',
    ...(identity ? { accountType: viewerIsRoot ? 'root' : 'admin' } : {}),
    rbac: {
      compat: false, legacyGrantsPending: 0,
      ...(identity ? {
        identity: true,
        root: {
          email: viewerIsRoot ? 'admin-1@x.z' : 'root-1@x.z',
          confirmed: viewer !== 'unconfirmed-root' && viewer !== 'unconfirmed-root-viewer',
          chosenAt: null,
        },
      } : {}),
    },
  }
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function renderPage() {
  render(<AlertProvider><UsersPage /></AlertProvider>)
}
const rowEl = (name: string) => screen.getByText(name).closest('tr') as HTMLElement
const rowOf = (name: string) => within(rowEl(name))
const cell = (name: string, header: string) => {
  const headers = screen.getAllByRole('columnheader').map((th) => th.textContent)
  return within(rowEl(name).querySelectorAll('td')[headers.indexOf(header)] as HTMLElement)
}
/** The controls a row offers, by accessible name. */
function actionsOf(name: string): string[] {
  const r = rowOf(name)
  return [
    ...r.queryAllByRole('combobox').map((c) => c.getAttribute('aria-label') ?? ''),
    ...r.queryAllByRole('button').map((b) => b.getAttribute('aria-label') ?? b.textContent ?? ''),
  ]
}

beforeEach(() => {
  h.list = { data: rows(), isLoading: false, error: null }
  h.isAdmin = true
  h.refetch.mockReset()
  h.create.mockReset().mockResolvedValue({})
  h.router.push.mockReset()
  h.router.replace.mockReset()
  h.fetch.mockReset()
  h.fetch.mockImplementation(async () => json({ error: 'Forbidden' }, 403))
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('columns', () => {
  test('switch off: Phase 1 columns plus status and last login; no type, no must-change', () => {
    as('admin-off')
    renderPage()
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent))
      .toEqual(['Name', 'Email', 'Role', 'Status', 'Password', 'Projects', 'Last login', 'Actions'])
    expect(cell('Ada', 'Role').getByText('admin')).toBeInTheDocument()
    expect(cell('Marco', 'Status').getByText('Active')).toBeInTheDocument()
    expect(cell('Anna', 'Status').getByText('Disabled')).toBeInTheDocument()
    expect(cell('Nina', 'Status').getByText('Invited')).toBeInTheDocument()
    expect(screen.queryByText('Must change password')).toBeNull()
    expect(screen.queryByText('Root')).toBeNull()
    expect(cell('Ada', 'Projects').getByText('4')).toBeInTheDocument()
  })

  test('last login: a time element with the exact instant, "Not recorded" without one', () => {
    for (const viewer of ['admin-off', 'admin-on'] as const) {
      as(viewer)
      renderPage()
      const time = cell('Marco', 'Last login').getByText((_, el) => el?.tagName === 'TIME') as HTMLTimeElement
      expect(time.dateTime).toBe(LOGIN)
      expect(time.textContent).not.toBe('')
      expect(cell('Pia', 'Last login').getByText('Not recorded')).toBeInTheDocument()
      cleanup()
    }
  })

  test('switch on: the account type in place of the role, and the must-change flag', () => {
    as('admin-on')
    renderPage()
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent))
      .toEqual(['Name', 'Email', 'Type', 'Status', 'Password', 'Projects', 'Last login', 'Actions'])
    expect(cell('Rita', 'Type').getByText('Root')).toBeInTheDocument()
    expect(cell('Pia', 'Type').getByText('Admin')).toBeInTheDocument()
    expect(cell('Ada', 'Type').getByText('Admin')).toBeInTheDocument()
    expect(cell('Marco', 'Type').getByText('Member')).toBeInTheDocument()
    expect(cell('Marco', 'Status').getByText('Must change password')).toBeInTheDocument()
    expect(cell('Pia', 'Status').queryByText('Must change password')).toBeNull()
    expect(cell('Nina', 'Status').getByText('Invited')).toBeInTheDocument()
  })

  test('switch on: an unconfirmed Root says so', () => {
    as('unconfirmed-root')
    renderPage()
    expect(cell('Rita', 'Type').getByText('Root')).toBeInTheDocument()
    expect(cell('Rita', 'Type').getByText('unconfirmed')).toBeInTheDocument()
  })

  test('switch on, the confirmed Root: its own row reads Root, the others keep the role control', () => {
    as('root')
    h.list.data = rows().filter((r) => r.id !== 'root-1')
    renderPage()
    expect(cell('Ada', 'Type').getByText('Root')).toBeInTheDocument()
    expect(cell('Pia', 'Type').getByRole('combobox', { name: 'Role of Pia' })).toBeInTheDocument()
  })
})

describe('actions per hierarchy', () => {
  test('switch off: Phase 1, any admin manages every other row; Enable on a disabled one', () => {
    as('admin-off')
    renderPage()
    expect(actionsOf('Pia')).toEqual(['Role of Pia', 'Set Password', 'Delete'])
    expect(actionsOf('Rita')).toEqual(['Role of Rita', 'Set Password', 'Delete'])
    expect(actionsOf('Marco')).toEqual(['Role of Marco', 'Set Password', 'Delete'])
    expect(actionsOf('Anna')).toEqual(['Role of Anna', 'Set Password', 'Delete', 'Enable Anna'])
    expect(actionsOf('Ada')).toEqual(['Set Password'])
  })

  test('switch on, an admin: members only; nothing on Root or another admin', () => {
    as('admin-on')
    renderPage()
    expect(actionsOf('Rita')).toEqual([])
    expect(actionsOf('Pia')).toEqual([])
    expect(actionsOf('Marco')).toEqual([
      'Set Password', 'Reset the credentials of Marco', 'Delete', 'Sign Marco out everywhere', 'Disable Marco',
    ])
    expect(actionsOf('Nina')).toEqual(['Resend the invite to Nina', 'Cancel the invite of Nina', 'Delete'])
    expect(actionsOf('Ada')).toEqual(['Set Password', 'Sign your account out everywhere'])
  })

  test('switch on, an unconfirmed Root: an admin until the host confirms it', () => {
    as('unconfirmed-root-viewer')
    h.list.data = rows().filter((r) => r.id !== 'root-1')
    renderPage()
    expect(actionsOf('Pia')).toEqual([])
    expect(actionsOf('Ada')).toEqual(['Set Password', 'Sign your account out everywhere'])
  })

  test('switch on, the confirmed Root: admins and members; its own row transfers Root', () => {
    as('root')
    h.list.data = rows().filter((r) => r.id !== 'root-1')
    renderPage()
    expect(actionsOf('Pia')).toEqual([
      'Role of Pia', 'Set Password', 'Reset the credentials of Pia', 'Delete', 'Sign Pia out everywhere', 'Disable Pia',
    ])
    expect(actionsOf('Ada')).toEqual(['Set Password', 'Transfer Root', 'Sign your account out everywhere'])
  })
})

describe('states', () => {
  test('loading', () => {
    as('admin-on')
    h.list = { data: undefined, isLoading: true, error: null }
    renderPage()
    expect(screen.getByRole('status').textContent).toBe('Loading users...')
    expect(screen.queryByRole('table')).toBeNull()
  })

  test('error: the cause, and Retry reads the list again', () => {
    as('admin-on')
    h.list = { data: undefined, isLoading: false, error: new Error('Failed to fetch users (P1001 · HTTP 500)') }
    renderPage()
    expect(screen.getByRole('alert').textContent).toBe('Failed to fetch users (P1001 · HTTP 500)')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(h.refetch).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('No users found')).toBeNull()
  })

  test('empty', () => {
    as('admin-off')
    h.list = { data: [], isLoading: false, error: null }
    renderPage()
    expect(screen.getByText('No users found')).toBeInTheDocument()
    expect(screen.queryByRole('table')).toBeNull()
  })

  test('denied: a member is sent to the graph and sees no list', () => {
    as('admin-on')
    h.isAdmin = false
    renderPage()
    expect(h.router.push).toHaveBeenCalledWith('/graph')
    expect(screen.queryByRole('table')).toBeNull()
  })
})

describe('passwordless creation stays available (ID-12)', () => {
  for (const viewer of ['admin-off', 'admin-on'] as const) {
    test(`${viewer}: an account without a password is created`, async () => {
      as(viewer)
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: /^(Create User|Create with a temporary password)$/ }))
      const dialog = within(screen.getByRole('dialog'))
      expect(dialog.getByText('Passwordless users can only be accessed via admin switching')).toBeInTheDocument()
      fireEvent.change(dialog.getByLabelText('Name *'), { target: { value: 'Managed' } })
      fireEvent.change(dialog.getByLabelText('Email *'), { target: { value: 'managed@x.z' } })
      fireEvent.click(dialog.getByRole('button', { name: 'Create User' }))
      await waitFor(() => expect(h.create).toHaveBeenCalledTimes(1))
      expect(h.create.mock.calls[0][0]).toMatchObject({ name: 'Managed', email: 'managed@x.z', password: undefined, role: 'standard' })
    })
  }
})
