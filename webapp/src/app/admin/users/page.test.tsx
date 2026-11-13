/**
 * The admin console's users directory (step 6.2; GV-01, ID-27; DV-06, DV-19): the accounts with
 * type, status, sets or profile, last sign-in and project counts; search, filters (kept in the
 * address, so `?set=<id>` lists a set's holders) and "Load more"; each row offers exactly the actions
 * the server listed for the signed-in person (hierarchy.ts) and the own row "Sign out everywhere";
 * confirmations go through the app's dialog; loading, error + Retry, denied and empty states; the
 * controls are labelled and reachable by keyboard. The console shell (6.1) denies the page to anyone
 * without users:read before it renders.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/users/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { AlertProvider } from '@/components/ui'
import type { PermissionId } from '@/lib/authz/permissions'
import type { DirectoryPage, DirectoryRow } from '@/lib/authz/userDirectory'

const h = vi.hoisted(() => ({
  search: '',
  replace: vi.fn(),
  push: vi.fn(),
  setUserId: vi.fn(async () => null),
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: h.replace, push: h.push }),
  useSearchParams: () => new URLSearchParams(h.search),
  usePathname: () => '/admin/users',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ setUserId: h.setUserId }) }))
vi.mock('@/hooks/usePasswordPolicy', () => ({ usePasswordPolicy: () => null }))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: [] }) }))
vi.mock('@/components/admin/LegacyAccessCard', () => ({ LegacyAccessCard: () => <section id="legacy-review">legacy review card</section> }))
vi.mock('@/components/admin/WhatChangedCard', () => ({ WhatChangedCard: () => <section>update notes card</section> }))

import AdminUsersPage from './page'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
const ALL_ACTIONS: DirectoryRow['actions'] = ['edit', 'assign_permissions', 'disable', 'reset_credentials', 'revoke_sessions', 'impersonate', 'delete']

function row(id: string, over: Partial<DirectoryRow> = {}): DirectoryRow {
  return {
    id, name: `${id} name`, email: `${id}@e2e.local`, accountType: 'member', status: 'active', mustChangePassword: false,
    lastLoginAt: null, createdAt: '2026-11-01T00:00:00.000Z', sets: [], profile: null, projects: { owned: 0, shared: null },
    self: false, actions: [], ...over,
  }
}

function page(users: DirectoryRow[], over: Partial<DirectoryPage> = {}): DirectoryPage {
  return {
    users, nextCursor: null, total: users.length, sharing: false,
    setOptions: [
      { id: 'builtin:recon-operator', name: 'Recon operator', kind: 'member' },
      { id: 'builtin:user-manager', name: 'User manager', kind: 'admin' },
    ],
    ...over,
  }
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let fetchMock: ReturnType<typeof vi.fn>
let directory: (url: URL) => Response

beforeEach(() => {
  h.search = ''
  h.replace.mockReset()
  h.push.mockReset()
  h.setUserId.mockReset().mockResolvedValue(null)
  directory = () => json(page([]))
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(String(input), 'http://redamon.test')
    if (url.pathname === '/api/admin/users') return directory(url)
    if (init?.method === 'DELETE' || init?.method === 'POST') return json({ ok: true })
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPage(held: PermissionId[] = ['users:read']) {
  const base = fakeAuth(FLAGS_GOV, held)
  const auth = { ...base, user: { ...base.user!, id: 'adm-a', name: 'Admin A', role: 'admin' as const, email: 'adm-a@e2e.local', accountType: 'admin' as const } }
  return render(
    <AuthContext.Provider value={auth}>
      <AlertProvider><AdminUsersPage /></AlertProvider>
    </AuthContext.Provider>,
  )
}

const directoryCalls = () => fetchMock.mock.calls
  .map(([u]) => new URL(String(u), 'http://redamon.test'))
  .filter((u) => u.pathname === '/api/admin/users')
const rowOf = (name: string) => screen.getByRole('link', { name }).closest('tr')!

describe('what the directory shows', () => {
  test('each account with type, status, sets or profile, last sign-in and project counts; the review cards stay on top', async () => {
    directory = () => json(page([
      row('root-1', { accountType: 'root', sets: null }),
      row('adm-b', { accountType: 'admin', sets: null, profile: { id: 'builtin:user-manager', name: 'User manager' }, lastLoginAt: '2026-11-12T09:30:00.000Z' }),
      row('m-1', { sets: [{ id: 'builtin:recon-operator', name: 'Recon operator' }, { id: 'set-gone', name: null }], projects: { owned: 3, shared: 2 } }),
      row('m-2', { status: 'disabled', mustChangePassword: true }),
    ], { sharing: true, total: 9, nextCursor: 'c1' }))
    renderPage()
    await screen.findByRole('link', { name: 'm-1 name' })
    expect(screen.getByText('legacy review card')).toBeInTheDocument()
    expect(screen.getByText('update notes card')).toBeInTheDocument()
    expect(screen.getByText('Showing 4 of 9 accounts')).toBeInTheDocument()
    expect(within(rowOf('root-1 name')).getByText('Root')).toBeInTheDocument()
    expect(within(rowOf('root-1 name')).getByText('Every permission')).toBeInTheDocument()
    const admin = within(rowOf('adm-b name'))
    expect(admin.getByText('Admin')).toBeInTheDocument()
    expect(admin.getByText('User manager')).toBeInTheDocument()
    expect(admin.getByRole('time')).toHaveAttribute('dateTime', '2026-11-12T09:30:00.000Z')
    const member = within(rowOf('m-1 name'))
    expect(member.getByRole('list', { name: 'Permission sets' }).textContent).toBe('Recon operatorDeleted set')
    expect(member.getByText('3')).toBeInTheDocument()
    expect(member.getByText(/2 shared/)).toBeInTheDocument()
    expect(member.getByText('Not recorded')).toBeInTheDocument()
    const disabled = within(rowOf('m-2 name'))
    expect(disabled.getByText('Disabled')).toBeInTheDocument()
    expect(disabled.getByText('Must change password')).toBeInTheDocument()
    expect(disabled.getByText('Default set')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'm-1 name' })).toHaveAttribute('href', '/admin/users/m-1')
  })

  test('without sharing in force no shared count is shown', async () => {
    directory = () => json(page([row('m-1', { projects: { owned: 1, shared: null } })]))
    renderPage()
    await screen.findByRole('link', { name: 'm-1 name' })
    expect(screen.queryByText(/shared/)).toBeNull()
  })
})

describe('filters and pagination', () => {
  test('search, status, type and set reach the API and the address; Clear filters drops them all', async () => {
    renderPage()
    await screen.findByText('No accounts yet.')
    fireEvent.change(screen.getByLabelText('Name or email'), { target: { value: ' ada ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await waitFor(() => expect(directoryCalls().at(-1)!.searchParams.get('q')).toBe('ada'))
    expect(h.replace).toHaveBeenLastCalledWith('/admin/users?q=ada', { scroll: false })

    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'disabled' } })
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'member' } })
    fireEvent.change(screen.getByLabelText('Set or profile'), { target: { value: 'builtin:user-manager' } })
    await waitFor(() => expect(Object.fromEntries(directoryCalls().at(-1)!.searchParams)).toEqual({
      q: 'ada', status: 'disabled', type: 'member', set: 'builtin:user-manager',
    }))
    expect(await screen.findByText('No account matches these filters.')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(directoryCalls().at(-1)!.search).toBe(''))
    expect(h.replace).toHaveBeenLastCalledWith('/admin/users', { scroll: false })
  })

  test('the set filter offers member sets and admin profiles in their own groups', async () => {
    renderPage()
    await screen.findByText('No accounts yet.')
    const select = screen.getByLabelText('Set or profile')
    expect(within(within(select).getByRole('group', { name: 'Member sets' })).getAllByRole('option').map((o) => o.textContent)).toEqual(['Recon operator'])
    expect(within(within(select).getByRole('group', { name: 'Admin profiles' })).getAllByRole('option').map((o) => o.textContent)).toEqual(['User manager'])
  })

  test('opened as /admin/users?set=<id>: the first read lists that set\'s holders', async () => {
    h.search = 'set=builtin:recon-operator&status=active'
    directory = () => json(page([row('m-1', { sets: [{ id: 'builtin:recon-operator', name: 'Recon operator' }] })]))
    renderPage()
    await screen.findByRole('link', { name: 'm-1 name' })
    expect(Object.fromEntries(directoryCalls()[0].searchParams)).toEqual({ set: 'builtin:recon-operator', status: 'active' })
    expect(screen.getByLabelText('Set or profile')).toHaveValue('builtin:recon-operator')
  })

  test('Load more asks the next page with the cursor and adds its rows; a failed one says so and keeps the rows', async () => {
    directory = (url) => (url.searchParams.get('cursor') === 'c1'
      ? json(page([row('m-2')], { total: 2 }))
      : json(page([row('m-1')], { total: 2, nextCursor: 'c1' })))
    renderPage()
    await screen.findByRole('link', { name: 'm-1 name' })
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await screen.findByRole('link', { name: 'm-2 name' })
    expect(screen.getByRole('link', { name: 'm-1 name' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
    expect(screen.getByText('Showing 2 of 2 accounts')).toBeInTheDocument()

    cleanup()
    directory = (url) => (url.searchParams.get('cursor')
      ? json({ error: 'Could not list the accounts', code: 'P1001' }, 500)
      : json(page([row('m-1')], { total: 2, nextCursor: 'c1' })))
    renderPage()
    await screen.findByRole('link', { name: 'm-1 name' })
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/P1001/)
    expect(screen.getByRole('link', { name: 'm-1 name' })).toBeInTheDocument()
  })
})

describe('row actions follow the hierarchy', () => {
  const buttons = (name: string) => within(rowOf(name)).queryAllByRole('button').map((b) => b.textContent)

  test('exactly the actions the server listed: none, all, an invite\'s, a disabled account\'s, the own row\'s', async () => {
    directory = () => json(page([
      row('adm-b', { accountType: 'admin', sets: null, profile: { id: 'builtin:full-admin', name: 'Full admin' } }),
      row('m-1', { actions: ALL_ACTIONS }),
      row('m-2', { status: 'invited', actions: ['create', 'edit', 'assign_permissions', 'delete'] }),
      row('m-3', { status: 'disabled', actions: ['edit', 'enable'] }),
      row('m-4', { actions: ['revoke_sessions'] }),
      row('adm-a', { accountType: 'admin', self: true, sets: null, profile: { id: 'builtin:full-admin', name: 'Full admin' } }),
    ]))
    renderPage()
    await screen.findByRole('link', { name: 'm-1 name' })
    expect(buttons('adm-b name')).toEqual([])
    expect(buttons('m-1 name')).toEqual(['Edit', 'Reset credentials', 'Act as', 'Sign out everywhere', 'Disable', 'Delete'])
    expect(within(rowOf('m-1 name')).getByRole('link', { name: 'Permissions of m-1 name' })).toHaveAttribute('href', '/admin/users/m-1#permissions')
    expect(buttons('m-2 name')).toEqual(['Resend', 'Cancel invite', 'Edit', 'Delete'])
    expect(buttons('m-3 name')).toEqual(['Edit', 'Enable'])
    // Signing out without disabling: the status buttons follow the list one by one.
    expect(buttons('m-4 name')).toEqual(['Sign out everywhere'])
    expect(buttons('adm-a name')).toEqual(['Sign out everywhere'])
    expect(within(rowOf('adm-a name')).getByText('(you)')).toBeInTheDocument()
  })

  test('Act as opens the act-as dialog for that account (the project provider asks the reason and password)', async () => {
    directory = () => json(page([row('m-1', { actions: ['impersonate'] })]))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Act as m-1 name' }))
    await waitFor(() => expect(h.setUserId).toHaveBeenCalledWith('m-1', {
      target: { id: 'm-1', name: 'm-1 name', email: 'm-1@e2e.local', accountType: 'member' },
    }))
  })

  test('Delete asks in the app\'s dialog first: cancelled sends nothing, confirmed deletes and reads the list again', async () => {
    directory = () => json(page([row('m-1', { actions: ['delete'] })]))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete m-1 name' }))
    let dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toMatch(/Delete m-1 name \(m-1@e2e\.local\)\?/)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false)

    const reads = directoryCalls().length
    fireEvent.click(screen.getByRole('button', { name: 'Delete m-1 name' }))
    dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/users/m-1', expect.objectContaining({ method: 'DELETE' })))
    await waitFor(() => expect(directoryCalls().length).toBe(reads + 1))
  })

  test('deleting an admin asks for the person\'s own password and sends it', async () => {
    directory = () => json(page([row('adm-b', { accountType: 'admin', sets: null, profile: { id: 'builtin:user-manager', name: 'User manager' }, actions: ['delete'] })]))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete adm-b name' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'own-passphrase' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/users/adm-b', expect.objectContaining({
      method: 'DELETE', body: JSON.stringify({ stepUpPassword: 'own-passphrase' }),
    })))
  })

  test('Edit sends the new name alone; a new email needs the person\'s password', async () => {
    directory = () => json(page([row('m-1', { actions: ['edit'] })]))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit m-1 name' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByLabelText('Your password')).toBeNull()
    fireEvent.change(within(dialog).getByLabelText('Sign-in email'), { target: { value: 'new@e2e.local' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect((await within(dialog).findByRole('alert')).textContent).toBe('Enter your password to confirm this change')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'own-passphrase' } })
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Renamed' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/users/m-1', expect.objectContaining({
      method: 'PUT', body: JSON.stringify({ name: 'Renamed', email: 'new@e2e.local', stepUpPassword: 'own-passphrase' }),
    })))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  test('Invite user shows only to a users:create holder', async () => {
    renderPage(['users:read'])
    await screen.findByText('No accounts yet.')
    expect(screen.queryByRole('button', { name: 'Invite user' })).toBeNull()
    cleanup()
    renderPage(['users:read', 'users:create'])
    await screen.findByText('No accounts yet.')
    expect(screen.getByRole('button', { name: 'Invite user' })).toBeInTheDocument()
  })
})

describe('states', () => {
  test('loading, then the error with its code and Retry, which reads again', async () => {
    let fail = true
    directory = () => (fail ? json({ error: 'Could not list the accounts', code: 'P1001' }, 500) : json(page([row('m-1')])))
    renderPage()
    expect(screen.getByRole('status').textContent).toBe('Loading the accounts…')
    expect((await screen.findByRole('alert')).textContent).toMatch(/P1001/)
    fail = false
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await screen.findByRole('link', { name: 'm-1 name' })
  })

  test('denied: the route\'s 403 names the permission', async () => {
    directory = () => json({ error: 'You do not hold the permission this action needs (users:read).', code: 'forbidden', permission: 'users:read' }, 403)
    renderPage()
    const notice = await screen.findByRole('alert')
    expect(notice.textContent).toMatch(/users:read/)
    expect(screen.queryByRole('table')).toBeNull()
  })

  test('empty: no accounts, and no match for the filters, say which', async () => {
    renderPage()
    expect(await screen.findByText('No accounts yet.')).toBeInTheDocument()
    cleanup()
    h.search = 'q=nobody'
    renderPage()
    expect(await screen.findByText('No account matches these filters.')).toBeInTheDocument()
  })
})

describe('keyboard and labels', () => {
  test('a labelled search landmark, labelled filters, a labelled table, links and buttons in the tab order', async () => {
    directory = () => json(page([row('m-1', { actions: ['edit'] })], { nextCursor: 'c1' }))
    renderPage()
    await screen.findByRole('link', { name: 'm-1 name' })
    expect(screen.getByRole('search', { name: 'Find accounts' })).toBeInTheDocument()
    for (const label of ['Name or email', 'Status', 'Type', 'Set or profile']) expect(screen.getByLabelText(label)).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Accounts' })).toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map((c) => c.textContent)).toEqual(
      ['Account', 'Type', 'Status', 'Sets or profile', 'Last sign-in', 'Projects', 'Actions'])
    for (const el of [...screen.getAllByRole('button'), ...screen.getAllByRole('link')]) expect(el).not.toHaveAttribute('tabindex', '-1')
    // Enter in the search field submits it.
    fireEvent.change(screen.getByLabelText('Name or email'), { target: { value: 'm-1' } })
    fireEvent.submit(screen.getByRole('search', { name: 'Find accounts' }))
    await waitFor(() => expect(directoryCalls().at(-1)!.searchParams.get('q')).toBe('m-1'))
  })
})
