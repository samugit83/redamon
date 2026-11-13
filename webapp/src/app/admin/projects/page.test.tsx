/**
 * The admin console's Projects section (step 6.4; GV-04, SH-18; DV-06, DV-19): every project with its
 * owner, scope, live shares and last activity; search and "Load more"; "Open read-only" only where the
 * server offers it (sharing in force, not acting as someone); a project's shares listed in its row
 * when they may be listed; Root's forced delete and force-revoke behind the app's confirmation and
 * Root's password; loading, error + Retry, denied and empty states; labelled controls. The console
 * shell (6.1) denies the page to anyone without projects:oversee before it renders.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/projects/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { AlertProvider } from '@/components/ui'
import type { AdminProjectRow, ProjectsOverview } from '@/lib/authz/adminProjects'
import type { AdminShareRow, SharesOverview } from '@/lib/authz/adminShares'

const h = vi.hoisted(() => ({
  search: '',
  replace: vi.fn(),
  sections: [] as Array<{ id: string }>,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: h.replace, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(h.search),
  usePathname: () => '/admin/projects',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))
vi.mock('@/app/admin/AdminConsole', () => ({ useConsoleSections: () => h.sections }))

import AdminProjectsPage from './page'

const FLAGS_GOV = { ...FLAGS_ON, governance: true, sharing: true }
const NO_ACTIONS = { openReadOnly: false, breakGlass: false, delete: false, revokeShares: false }

function project(id: string, over: Partial<AdminProjectRow> = {}): AdminProjectRow {
  return {
    id, name: `${id} name`, targetLabel: `${id}.example.test`,
    owner: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local', status: 'active' },
    collaborators: 0, createdAt: '2026-11-01T08:00:00.000Z', lastActivityAt: '2026-11-12T09:00:00.000Z', ...over,
  }
}

function page(projects: AdminProjectRow[], over: Partial<ProjectsOverview> = {}): ProjectsOverview {
  return {
    projects, nextCursor: null, total: projects.length,
    sharing: { inForce: true, allShares: true }, actions: { openReadOnly: true, breakGlass: false, delete: false, revokeShares: false }, ...over,
  }
}

function share(over: Partial<AdminShareRow> = {}): AdminShareRow {
  return {
    project: { id: 'p-1', name: 'p-1 name' }, owner: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local' },
    collaborator: { id: 'mem-b', name: 'Member B', email: 'mem-b@e2e.local', status: 'active' },
    access: 'read', toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: false },
    expiresAt: null, expired: false, createdAt: '2026-11-10T08:00:00.000Z', ...over,
  }
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let fetchMock: ReturnType<typeof vi.fn>
let projectsAnswer: (url: URL) => Response
let sharesAnswer: (url: URL) => Response
let deleteAnswer: (url: URL, body: Record<string, unknown>) => Response

beforeEach(() => {
  h.search = ''
  h.replace.mockReset()
  h.sections = [{ id: 'projects' }, { id: 'shares' }, { id: 'users' }]
  projectsAnswer = () => json(page([]))
  sharesAnswer = () => json({ shares: [], nextCursor: null, total: 0, actions: { revoke: false } } satisfies SharesOverview)
  deleteAnswer = (url) => json(url.pathname.startsWith('/api/admin/shares/')
    ? { revoked: {}, forced: true, socketsClosed: true }
    : { deleted: { projectId: 'p-1', ownerId: 'mem-a' } })
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(String(input), 'http://redamon.test')
    if (init?.method === 'DELETE') return deleteAnswer(url, JSON.parse(String(init.body)))
    if (init?.method === 'POST') return json({ breakGlass: { id: 'bg-1', projectId: 'p-1', expiresAt: '2026-11-13T13:00:00.000Z', durationMinutes: 60 } }, 201)
    if (url.pathname === '/api/admin/projects') return projectsAnswer(url)
    if (url.pathname === '/api/admin/shares') return sharesAnswer(url)
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPage(id = 'adm-a') {
  const base = fakeAuth(FLAGS_GOV, ['projects:oversee', 'users:read'])
  const auth = { ...base, user: { ...base.user!, id, name: 'Admin', role: 'admin' as const, email: `${id}@e2e.local`, accountType: 'admin' as const } }
  return render(<AuthContext.Provider value={auth}><AlertProvider><AdminProjectsPage /></AlertProvider></AuthContext.Provider>)
}

const calls = (path: string) => fetchMock.mock.calls
  .filter(([, init]) => (init as RequestInit | undefined)?.method !== 'DELETE')
  .map(([u]) => new URL(String(u), 'http://redamon.test')).filter((u) => u.pathname === path)
const deletes = () => fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE')
  .map(([u, init]) => ({ path: new URL(String(u), 'http://redamon.test').pathname, body: JSON.parse(String((init as RequestInit).body)) }))
const rowOf = (name: string) => screen.getByText(name).closest('tr')!

describe('the oversight list', () => {
  test('each project with owner, scope, share count and activity; the owner links to the account', async () => {
    projectsAnswer = () => json(page([
      project('p-1', { collaborators: 0 }),
      project('p-2', { owner: { id: 'mem-b', name: 'Member B', email: 'mem-b@e2e.local', status: 'disabled' }, collaborators: 3 }),
    ], { total: 2 }))
    renderPage()
    const p1Row = (await screen.findByText('p-1 name')).closest('tr')!
    const p1 = within(p1Row)
    expect(p1.getByText('p-1.example.test')).toBeInTheDocument()
    expect(p1.getByRole('link', { name: 'Member A' })).toHaveAttribute('href', '/admin/users/mem-a')
    expect(p1.getByText('mem-a@e2e.local')).toBeInTheDocument()
    expect(p1.getByText('0')).toBeInTheDocument()
    expect(p1Row.querySelector('time[datetime="2026-11-12T09:00:00.000Z"]')).not.toBeNull()
    expect(p1Row.querySelector('time[datetime="2026-11-01T08:00:00.000Z"]')).not.toBeNull()
    const p2 = within(rowOf('p-2 name'))
    expect(p2.getByText('(disabled)')).toBeInTheDocument()
    expect(p2.getByRole('button', { name: 'Show 3 shares' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByText('Showing 2 of 2 projects')).toBeInTheDocument()
    expect(calls('/api/admin/projects')[0].search).toBe('')
  })

  test('without the Users section the owner is plain text', async () => {
    h.sections = [{ id: 'projects' }]
    projectsAnswer = () => json(page([project('p-1', { collaborators: 2 })]))
    renderPage()
    const row = within(await screen.findByText('p-1 name').then((n) => n.closest('tr')!))
    expect(row.queryByRole('link', { name: 'Member A' })).toBeNull()
    // Without the Shares section (users:read and the policy) the count is not a list.
    expect(row.queryByRole('button', { name: /shares/ })).toBeNull()
    expect(row.getByText('2')).toBeInTheDocument()
  })

  test('sharing not in force: counts say so, nothing opens read-only', async () => {
    projectsAnswer = () => json(page([project('p-1', { collaborators: null })], { sharing: { inForce: false, allShares: false }, actions: NO_ACTIONS }))
    renderPage()
    const row = within(await screen.findByText('p-1 name').then((n) => n.closest('tr')!))
    expect(row.getByText('Not in force')).toBeInTheDocument()
    expect(row.queryByRole('link', { name: /Open/ })).toBeNull()
    expect(screen.getByText(/Sharing is not in force/)).toBeInTheDocument()
  })
})

describe('actions need their permission (the server says which a row offers)', () => {
  test('open read-only goes to the project page; own projects just "Open"; none when not offered', async () => {
    projectsAnswer = () => json(page([project('p-1'), project('p-2', { owner: { id: 'adm-a', name: 'Admin', email: 'adm-a@e2e.local', status: 'active' } })]))
    renderPage()
    expect(await screen.findByRole('link', { name: 'Open p-1 name read-only' })).toHaveAttribute('href', '/graph?project=p-1')
    expect(screen.getByRole('link', { name: 'Open p-2 name' })).toHaveAttribute('href', '/graph?project=p-2')
    expect(screen.queryByRole('button', { name: /^Delete/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /break-glass/ })).toBeNull()
    cleanup()
    projectsAnswer = () => json(page([project('p-1')], { actions: NO_ACTIONS }))
    renderPage()
    await screen.findByText('p-1 name')
    expect(screen.queryByRole('link', { name: /Open/ })).toBeNull()
  })

  test("Root's delete: the app's confirmation (cancel sends nothing), then Root's password, then the DELETE", async () => {
    projectsAnswer = () => json(page([project('p-1')], { actions: { openReadOnly: true, breakGlass: true, delete: true, revokeShares: true } }))
    renderPage('root-1')
    fireEvent.click(await screen.findByRole('button', { name: 'Delete p-1 name' }))
    let dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('cannot be undone')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(deletes()).toEqual([])

    fireEvent.click(screen.getByRole('button', { name: 'Delete p-1 name' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue' }))
    dialog = await screen.findByRole('dialog')
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByLabelText('Your password')).toBeInTheDocument())
    dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete the project' }))
    await waitFor(() => expect(deletes()).toEqual([{ path: '/api/admin/projects/p-1', body: { stepUpPassword: 'root-pass' } }]))
    expect(await screen.findByRole('status')).toHaveTextContent('Deleted p-1 name (owned by Member A).')
    await waitFor(() => expect(calls('/api/admin/projects')).toHaveLength(2))
  })

  test("Root's break-glass through step 4.14's dialog and route; never on Root's own project", async () => {
    projectsAnswer = () => json(page([
      project('p-1'),
      project('p-2', { owner: { id: 'root-1', name: 'Root', email: 'root@e2e.local', status: 'active' } }),
    ], { actions: { openReadOnly: true, breakGlass: true, delete: true, revokeShares: false } }))
    renderPage('root-1')
    fireEvent.click(await screen.findByRole('button', { name: 'Open break-glass on p-1 name' }))
    expect(screen.queryByRole('button', { name: 'Open break-glass on p-2 name' })).toBeNull()
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('Member A (mem-a@e2e.local) will be told')
    fireEvent.change(within(dialog).getByLabelText('Reason (required)'), { target: { value: 'incident 7' } })
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open break-glass' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const posts = fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')
    expect(posts).toHaveLength(1)
    expect(new URL(String(posts[0][0]), 'http://redamon.test').pathname).toBe('/api/projects/p-1/breakglass')
    expect(JSON.parse(String((posts[0][1] as RequestInit).body))).toEqual({ reason: 'incident 7', durationMinutes: 60, stepUpPassword: 'root-pass' })
    expect(screen.getByRole('status')).toHaveTextContent('Break-glass open on p-1 name until')
  })

  test('a wrong password keeps the dialog open with the refusal', async () => {
    projectsAnswer = () => json(page([project('p-1')], { actions: { openReadOnly: true, breakGlass: true, delete: true, revokeShares: false } }))
    deleteAnswer = () => json({ error: 'Password is incorrect', code: 'step_up_failed' }, 403)
    renderPage('root-1')
    fireEvent.click(await screen.findByRole('button', { name: 'Delete p-1 name' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByLabelText('Your password')).toBeInTheDocument())
    fireEvent.change(within(screen.getByRole('dialog')).getByLabelText('Your password'), { target: { value: 'nope' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete the project' }))
    await waitFor(() => expect(screen.getByRole('dialog').textContent).toContain('Password is incorrect'))
    expect(screen.getByRole('dialog').textContent).toContain('step_up_failed')
  })

  test("a project's shares in its row; Root revokes one with its password", async () => {
    projectsAnswer = () => json(page([project('p-1', { collaborators: 1 })], { actions: { openReadOnly: true, breakGlass: true, delete: true, revokeShares: true } }))
    sharesAnswer = () => json({ shares: [share()], nextCursor: null, total: 1, actions: { revoke: true } } satisfies SharesOverview)
    renderPage('root-1')
    const toggle = await screen.findByRole('button', { name: 'Show 1 share' })
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    const table = await screen.findByRole('table', { name: 'Shares of p-1 name' })
    expect(calls('/api/admin/shares')[0].search).toBe('?project=p-1&limit=100')
    expect(within(table).getByText('Read · Raw data')).toBeInTheDocument()
    expect(within(table).getByText('Never')).toBeInTheDocument()
    fireEvent.click(within(table).getByRole('button', { name: "Revoke Member B's share of p-1 name" }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByLabelText('Your password')).toBeInTheDocument())
    fireEvent.change(within(screen.getByRole('dialog')).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke the share' }))
    await waitFor(() => expect(deletes()).toEqual([{ path: '/api/admin/shares/p-1/mem-b', body: { stepUpPassword: 'root-pass' } }]))
    expect(await screen.findByRole('status')).toHaveTextContent("Revoked Member B's share of p-1 name.")
  })

  test('an admin who lists the shares gets no Revoke; an unshared project says so', async () => {
    projectsAnswer = () => json(page([project('p-1', { collaborators: 1 })]))
    sharesAnswer = () => json({ shares: [share()], nextCursor: null, total: 1, actions: { revoke: false } } satisfies SharesOverview)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Show 1 share' }))
    const table = await screen.findByRole('table', { name: 'Shares of p-1 name' })
    expect(within(table).queryByRole('button', { name: /Revoke/ })).toBeNull()
    sharesAnswer = () => json({ shares: [], nextCursor: null, total: 0, actions: { revoke: false } } satisfies SharesOverview)
    fireEvent.click(screen.getByRole('button', { name: 'Hide 1 share' }))
    fireEvent.click(screen.getByRole('button', { name: 'Show 1 share' }))
    expect(await screen.findByText('p-1 name is not shared with anyone.')).toBeInTheDocument()
  })

  test("a row's shares that fail to load: the error and Retry", async () => {
    projectsAnswer = () => json(page([project('p-1', { collaborators: 1 })]))
    sharesAnswer = () => json({ error: 'Could not list the shares', code: 'P1001' }, 500)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Show 1 share' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    sharesAnswer = () => json({ shares: [share()], nextCursor: null, total: 1, actions: { revoke: false } } satisfies SharesOverview)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('table', { name: 'Shares of p-1 name' })).toBeInTheDocument()
  })
})

describe('search and paging', () => {
  test('search goes to the address and the list; Load more sends the cursor; Clear filters', async () => {
    projectsAnswer = (url) => json(url.searchParams.get('cursor')
      ? page([project('p-3')], { total: 3 })
      : page([project('p-1'), project('p-2')], { total: 3, nextCursor: 'c-1' }))
    renderPage()
    await screen.findByText('p-1 name')
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('p-3 name')).toBeInTheDocument()
    expect(calls('/api/admin/projects')[1].searchParams.get('cursor')).toBe('c-1')
    fireEvent.change(screen.getByLabelText('Project or owner'), { target: { value: 'acme' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect(h.replace).toHaveBeenCalledWith('/admin/projects?q=acme', { scroll: false })
    await waitFor(() => expect(calls('/api/admin/projects').at(-1)!.searchParams.get('q')).toBe('acme'))
    fireEvent.click(await screen.findByRole('button', { name: 'Clear filters' }))
    expect(h.replace).toHaveBeenLastCalledWith('/admin/projects', { scroll: false })
  })

  test('?owner=<id> from the address lists one account and says so', async () => {
    h.search = 'owner=mem-a'
    projectsAnswer = () => json(page([project('p-1')]))
    renderPage()
    await screen.findByText('p-1 name')
    expect(calls('/api/admin/projects')[0].searchParams.get('owner')).toBe('mem-a')
    expect(screen.getByText("Showing one account's projects only.")).toBeInTheDocument()
  })
})

describe('states and labels', () => {
  test('loading, then empty', async () => {
    renderPage()
    expect(screen.getByRole('status')).toHaveTextContent('Loading the projects')
    expect(await screen.findByText('No projects yet.')).toBeInTheDocument()
  })

  test('empty with filters', async () => {
    h.search = 'q=zzz'
    renderPage()
    expect(await screen.findByText('No project matches these filters.')).toBeInTheDocument()
  })

  test('error with its code, and Retry', async () => {
    projectsAnswer = () => json({ error: 'Could not list the projects', code: 'P1001' }, 500)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    projectsAnswer = () => json(page([project('p-1')]))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('p-1 name')).toBeInTheDocument()
  })

  test('denied: the 403 naming projects:oversee', async () => {
    projectsAnswer = () => json({ error: 'You do not hold the permission', code: 'forbidden', permission: 'projects:oversee' }, 403)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('projects:oversee')
  })

  test('labelled controls, no control taken out of the tab order', async () => {
    projectsAnswer = () => json(page([project('p-1', { collaborators: 1 })], { actions: { openReadOnly: true, breakGlass: true, delete: true, revokeShares: true } }))
    const { container } = renderPage('root-1')
    await screen.findByText('p-1 name')
    expect(screen.getByRole('search', { name: 'Find projects' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Projects' })).toBeInTheDocument()
    expect(screen.getByLabelText('Project or owner')).toHaveAttribute('type', 'search')
    for (const b of screen.getAllByRole('button')) expect(b).toHaveAccessibleName()
    expect(container.querySelector('[tabindex="-1"]')).toBeNull()
  })
})
