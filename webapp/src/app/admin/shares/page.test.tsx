/**
 * The admin console's Shares section (step 6.4; GV-05, GV-20, SH-18; DV-06, DV-19): every share with
 * project, owner, person, level and toggles, expiry (expired marked) and when it was granted; search,
 * the project or account filter from the address, "Load more"; Root's force-revoke behind the app's
 * confirmation and Root's password; the hidden state when the route says the policy hides shares (it
 * changed after the console read it); loading, error + Retry, denied and empty states; labels. The
 * level words are pinned at the end (shareWords.ts).
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/shares/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { AlertProvider } from '@/components/ui'
import type { AdminShareRow, SharesOverview } from '@/lib/authz/adminShares'

const h = vi.hoisted(() => ({
  search: '',
  replace: vi.fn(),
  sections: [] as Array<{ id: string }>,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: h.replace, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(h.search),
  usePathname: () => '/admin/shares',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))
vi.mock('@/app/admin/AdminConsole', () => ({ useConsoleSections: () => h.sections }))

import AdminSharesPage from './page'
import { shareLevelLabel } from './shareWords'

const FLAGS_GOV = { ...FLAGS_ON, governance: true, sharing: true }
const OFF = { rawData: false, runScans: false, useAgent: false, exploit: false, manage: false }

function share(over: Partial<AdminShareRow> = {}): AdminShareRow {
  return {
    project: { id: 'p-1', name: 'Lab' }, owner: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local' },
    collaborator: { id: 'mem-b', name: 'Member B', email: 'mem-b@e2e.local', status: 'active' },
    access: 'read', toggles: { ...OFF, rawData: true }, expiresAt: null, expired: false, createdAt: '2026-11-10T08:00:00.000Z', ...over,
  }
}

const overview = (shares: AdminShareRow[], over: Partial<SharesOverview> = {}): SharesOverview =>
  ({ shares, nextCursor: null, total: shares.length, actions: { revoke: false }, ...over })

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let fetchMock: ReturnType<typeof vi.fn>
let sharesAnswer: (url: URL) => Response
let revokeAnswer: () => Response

beforeEach(() => {
  h.search = ''
  h.replace.mockReset()
  h.sections = [{ id: 'shares' }, { id: 'users' }]
  sharesAnswer = () => json(overview([]))
  revokeAnswer = () => json({ revoked: { projectId: 'p-1', userId: 'mem-b' }, forced: true, socketsClosed: true })
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(String(input), 'http://redamon.test')
    if (init?.method === 'DELETE') return revokeAnswer()
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
  const base = fakeAuth(FLAGS_GOV, ['users:read'])
  const auth = { ...base, user: { ...base.user!, id, name: 'Admin', role: 'admin' as const, email: `${id}@e2e.local`, accountType: 'admin' as const } }
  return render(<AuthContext.Provider value={auth}><AlertProvider><AdminSharesPage /></AlertProvider></AuthContext.Provider>)
}

const listCalls = () => fetchMock.mock.calls
  .filter(([, init]) => (init as RequestInit | undefined)?.method !== 'DELETE')
  .map(([u]) => new URL(String(u), 'http://redamon.test'))
const deletes = () => fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE')
  .map(([u, init]) => ({ path: new URL(String(u), 'http://redamon.test').pathname, body: JSON.parse(String((init as RequestInit).body)) }))

describe('what the overview shows', () => {
  test('each share with project, owner, person, level, expiry and grant date; expired marked; people link to their accounts', async () => {
    sharesAnswer = () => json(overview([
      share(),
      share({
        project: { id: 'p-2', name: 'Range' },
        collaborator: { id: 'mem-c', name: 'Member C', email: 'mem-c@e2e.local', status: 'disabled' },
        toggles: OFF, expiresAt: '2026-11-12T00:00:00.000Z', expired: true,
      }),
    ]))
    renderPage()
    const table = await screen.findByRole('table', { name: 'Shares' })
    const lab = within(within(table).getByText('Lab').closest('tr')!)
    expect(lab.getByRole('link', { name: 'Member A' })).toHaveAttribute('href', '/admin/users/mem-a')
    expect(lab.getByRole('link', { name: 'Member B' })).toHaveAttribute('href', '/admin/users/mem-b')
    expect(lab.getByText('Read · Raw data')).toBeInTheDocument()
    expect(lab.getByText('Never')).toBeInTheDocument()
    expect(lab.queryByText('Expired')).toBeNull()
    const range = within(within(table).getByText('Range').closest('tr')!)
    expect(range.getByText('Read')).toBeInTheDocument()
    expect(range.getByText('Expired')).toBeInTheDocument()
    expect(range.getByText('(disabled)')).toBeInTheDocument()
    expect(screen.getByText('Showing 2 of 2 shares')).toBeInTheDocument()
    // An admin who may not force-revoke gets no Actions column.
    expect(within(table).queryByRole('button', { name: /Revoke/ })).toBeNull()
  })

  test('without the Users section people are plain text', async () => {
    h.sections = [{ id: 'shares' }]
    sharesAnswer = () => json(overview([share()]))
    renderPage()
    const table = await screen.findByRole('table', { name: 'Shares' })
    expect(within(table).queryByRole('link')).toBeNull()
    expect(within(table).getByText('Member B')).toBeInTheDocument()
  })

  test("shares list hidden when the policy says so (changed after the console read it): the hidden state", async () => {
    sharesAnswer = () => json({ error: 'The instance sharing policy does not let administrators see every share.', code: 'shares_hidden' }, 403)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Shares are not listed here now.')
    cleanup()
    sharesAnswer = () => json({ error: 'Not found' }, 404)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Shares are not listed here now.')
  })
})

describe("Root's force-revoke", () => {
  test('confirmation (cancel sends nothing), password, DELETE, notice, list read again', async () => {
    sharesAnswer = () => json(overview([share()], { actions: { revoke: true } }))
    renderPage('root-1')
    const button = await screen.findByRole('button', { name: "Revoke Member B's share of Lab" })
    fireEvent.click(button)
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('Member B (mem-b@e2e.local) loses access to Lab')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(deletes()).toEqual([])
    fireEvent.click(button)
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByLabelText('Your password')).toBeInTheDocument())
    fireEvent.change(within(screen.getByRole('dialog')).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke the share' }))
    await waitFor(() => expect(deletes()).toEqual([{ path: '/api/admin/shares/p-1/mem-b', body: { stepUpPassword: 'root-pass' } }]))
    expect(await screen.findByRole('status')).toHaveTextContent("Revoked Member B's share of Lab.")
    await waitFor(() => expect(listCalls()).toHaveLength(2))
  })

  test('the agent did not confirm the socket close: the notice says so', async () => {
    sharesAnswer = () => json(overview([share()], { actions: { revoke: true } }))
    revokeAnswer = () => json({ revoked: {}, forced: true, socketsClosed: false })
    renderPage('root-1')
    fireEvent.click(await screen.findByRole('button', { name: "Revoke Member B's share of Lab" }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByLabelText('Your password')).toBeInTheDocument())
    fireEvent.change(within(screen.getByRole('dialog')).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke the share' }))
    expect(await screen.findByRole('status')).toHaveTextContent('The agent did not confirm closing their open sessions on it.')
  })

  test('a refusal (root_only) stays in the password dialog', async () => {
    sharesAnswer = () => json(overview([share()], { actions: { revoke: true } }))
    revokeAnswer = () => json({ error: 'Only Root can remove a share it did not grant.', code: 'root_only' }, 403)
    renderPage('root-1')
    fireEvent.click(await screen.findByRole('button', { name: "Revoke Member B's share of Lab" }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByLabelText('Your password')).toBeInTheDocument())
    fireEvent.change(within(screen.getByRole('dialog')).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke the share' }))
    await waitFor(() => expect(screen.getByRole('dialog').textContent).toContain('root_only'))
  })
})

describe('search, filters and paging', () => {
  test('?project=<id> narrows the list and says so; search and Clear filters keep the address', async () => {
    h.search = 'project=p-1'
    sharesAnswer = () => json(overview([share()]))
    renderPage()
    await screen.findByRole('table', { name: 'Shares' })
    expect(listCalls()[0].searchParams.get('project')).toBe('p-1')
    expect(screen.getByText("Showing one project's shares only.")).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Project, owner or person'), { target: { value: 'mem-b' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect(h.replace).toHaveBeenCalledWith('/admin/shares?q=mem-b&project=p-1', { scroll: false })
    fireEvent.click(await screen.findByRole('button', { name: 'Clear filters' }))
    expect(h.replace).toHaveBeenLastCalledWith('/admin/shares', { scroll: false })
  })

  test('Load more sends the cursor and appends', async () => {
    sharesAnswer = (url) => json(url.searchParams.get('cursor')
      ? overview([share({ project: { id: 'p-3', name: 'Third' } })], { total: 2 })
      : overview([share()], { total: 2, nextCursor: 'c-1' }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Third')).toBeInTheDocument()
    expect(listCalls()[1].searchParams.get('cursor')).toBe('c-1')
    expect(screen.getByText('Lab')).toBeInTheDocument()
  })
})

describe('states and labels', () => {
  test('loading, then empty; empty with filters', async () => {
    renderPage()
    expect(screen.getByRole('status')).toHaveTextContent('Loading the shares')
    expect(await screen.findByText('No project is shared yet.')).toBeInTheDocument()
    cleanup()
    h.search = 'q=zzz'
    renderPage()
    expect(await screen.findByText('No share matches these filters.')).toBeInTheDocument()
  })

  test('error with its code, and Retry', async () => {
    sharesAnswer = () => json({ error: 'Could not list the shares', code: 'P1001' }, 500)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    sharesAnswer = () => json(overview([share()]))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('table', { name: 'Shares' })).toBeInTheDocument()
  })

  test('denied: the 403 naming users:read', async () => {
    sharesAnswer = () => json({ error: 'You do not hold the permission', code: 'forbidden', permission: 'users:read' }, 403)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('users:read')
  })

  test('labelled controls, no control taken out of the tab order', async () => {
    sharesAnswer = () => json(overview([share()], { actions: { revoke: true } }))
    const { container } = renderPage('root-1')
    await screen.findByRole('table', { name: 'Shares' })
    expect(screen.getByRole('search', { name: 'Find shares' })).toBeInTheDocument()
    for (const b of screen.getAllByRole('button')) expect(b).toHaveAccessibleName()
    expect(container.querySelector('[tabindex="-1"]')).toBeNull()
  })
})

describe('the level words (shareWords.ts)', () => {
  test('Read, Read + Write, the toggles in order, an unknown level named', () => {
    expect(shareLevelLabel('read', OFF)).toBe('Read')
    expect(shareLevelLabel('read', { ...OFF, rawData: true })).toBe('Read · Raw data')
    expect(shareLevelLabel('write', { rawData: true, runScans: true, useAgent: true, exploit: true, manage: true }))
      .toBe('Read + Write · Raw data, Run scans, Use the agent, Exploitation & shells, Manage (co-owner)')
    expect(shareLevelLabel('owner', OFF)).toBe('Unknown level (owner)')
  })
})
