/**
 * The admin console's audit viewer (step 6.6; GV-07, AU-04, AU-07; DV-06, DV-19): three tabs (the
 * audit log, act-as, Fireteam settings), the rows newest first with the actor's identity label (a
 * deleted account by the email its row recorded), filters kept in the address, "Load more", a details
 * dialog (an audit log row's before/after read from the details route), the export of the current
 * filters for whoever holds audit:export (errors through the app's dialog), and the loading, error +
 * Retry, denied and empty states, with labelled, keyboard-reachable controls. The console shell (6.1)
 * denies the page to anyone without audit:read before it renders.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/audit/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { AlertProvider } from '@/components/ui'
import type { PermissionId } from '@/lib/authz/permissions'
import type { ActAsEntry, AuditLogEntry, AuditPage, AuditPerson, FireteamEntry } from '@/lib/authz/auditReader'

const h = vi.hoisted(() => ({ search: '', replace: vi.fn() }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: h.replace, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(h.search),
  usePathname: () => '/admin/audit',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))

import AdminAuditPage from './page'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
const person = (id: string, email: string, accountType: AuditPerson['accountType'], name = `${id} name`): AuditPerson =>
  ({ id, name, email, accountType, deleted: false })
const ROOT = person('root-1', 'root@e2e.local', 'root', 'Rhea')
const ADA = person('adm-a', 'ada@e2e.local', 'admin', 'Ada')
const MONA = person('mem-a', 'mona@e2e.local', 'member', 'Mona')
const GONE: AuditPerson = { id: 'del-9', name: '', email: 'gone@e2e.local', accountType: null, deleted: true }

function logEntry(id: string, over: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    kind: 'audit', id, at: '2026-11-13T11:00:00.000Z', action: 'user.update', label: 'Changed an account', group: 'accounts',
    actor: ADA, onBehalfOf: null, target: { type: 'user', id: 'mem-a', account: MONA }, project: null, permission: null, source: 'api', ...over,
  }
}
const actAs = (id: string, over: Partial<ActAsEntry> = {}): ActAsEntry => ({
  kind: 'act_as', id, at: '2026-11-13T10:00:00.000Z', event: 'start', label: 'Started acting as an account', admin: ADA, target: MONA,
  source: 'api', reason: 'ticket 42', durationMinutes: 30, endedBy: null, ...over,
})
const fireteam = (id: string): FireteamEntry => ({
  kind: 'fireteam', id, at: '2026-11-13T09:00:00.000Z', field: 'fireteamMaxConcurrent', project: { id: 'proj-1', name: 'Alpha' },
  user: MONA, oldValue: 2, newValue: 4, source: 'ui',
})
const pageOf = (entries: AuditPage['entries'], over: Partial<AuditPage> = {}): AuditPage =>
  ({ table: entries[0]?.kind ?? 'audit', entries, nextCursor: null, ...over })

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
let fetchMock: ReturnType<typeof vi.fn>
let list: (url: URL) => Response | Promise<Response>
let rowDetail: (id: string) => Response
let exportAnswer: (url: URL) => Response

beforeEach(() => {
  h.search = ''
  h.replace.mockReset()
  list = () => json(pageOf([]))
  rowDetail = (id) => json({ row: { ...logEntry(id), actorEmailRecorded: 'ada-then@e2e.local', before: null, after: { name: 'ci token', tokenPrefix: '[withheld]' } } })
  exportAnswer = () => new Response('id,at\r\n', {
    status: 200,
    headers: { 'content-disposition': 'attachment; filename="redamon-audit-audit-20261113T120000Z.csv"', 'x-audit-export-rows': '1', 'x-audit-export-total': '1', 'x-audit-export-truncated': 'false' },
  })
  fetchMock = vi.fn(async (input: string) => {
    const url = new URL(String(input), 'http://redamon.test')
    if (url.pathname === '/api/admin/audit') return list(url)
    if (url.pathname === '/api/admin/audit/export') return exportAnswer(url)
    if (url.pathname.startsWith('/api/admin/audit/')) return rowDetail(decodeURIComponent(url.pathname.split('/').pop()!))
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
  URL.createObjectURL = vi.fn(() => 'blob:audit')
  URL.revokeObjectURL = vi.fn()
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPage(held: PermissionId[] = ['audit:read']) {
  return render(
    <AuthContext.Provider value={fakeAuth(FLAGS_GOV, held)}>
      <AlertProvider><AdminAuditPage /></AlertProvider>
    </AuthContext.Provider>,
  )
}

const listCalls = () => fetchMock.mock.calls
  .map(([u]) => new URL(String(u), 'http://redamon.test'))
  .filter((u) => u.pathname === '/api/admin/audit')
const lastList = () => listCalls().at(-1)!

describe('what the viewer shows', () => {
  test('each audit row: time, label and action, the actor by identity label, on behalf of, target and project', async () => {
    list = () => json(pageOf([
      logEntry('r1', { action: 'project.share.grant', label: 'Shared the project', actor: MONA, onBehalfOf: null, target: { type: 'user', id: 'adm-a', account: ADA }, project: { id: 'proj-1', name: 'Alpha' } }),
      logEntry('r2', { actor: ADA, onBehalfOf: MONA, action: 'project.update', label: 'Changed the project settings', target: { type: 'project', id: 'proj-2', account: null }, project: { id: 'proj-2', name: null } }),
      logEntry('r3', { actor: GONE, action: 'mcp-token.create', label: 'Created an MCP token', target: { type: 'mcpAccessToken', id: 'tok-1', account: null } }),
      logEntry('r4', { actor: null, action: 'system.rbac_root_assigned', label: 'The Root was chosen automatically', target: { type: 'user', id: 'root-1', account: ROOT } }),
    ]))
    renderPage()
    const table = await screen.findByRole('table', { name: 'Audit log rows' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(4)
    expect(within(rows[0]).getByText('Shared the project')).toBeInTheDocument()
    expect(within(rows[0]).getByText('project.share.grant')).toBeInTheDocument()
    expect(within(rows[0]).getByRole('group', { name: 'Mona, mona@e2e.local, Member' })).toBeInTheDocument()
    expect(within(rows[0]).getByRole('group', { name: 'Ada, ada@e2e.local, Admin' })).toBeInTheDocument()
    expect(within(rows[0]).getByText('Alpha')).toBeInTheDocument()
    expect(within(rows[1]).getByRole('group', { name: 'Mona, mona@e2e.local, Member' })).toBeInTheDocument()
    // The target (a project id) and the project of a project row whose name is gone.
    expect(within(rows[1]).getAllByText('proj-2', { selector: 'code' })).toHaveLength(2)
    expect(within(rows[2]).getByText('Deleted account (gone@e2e.local)')).toBeInTheDocument()
    expect(within(rows[2]).getByText('mcpAccessToken')).toBeInTheDocument()
    expect(within(rows[3]).getByText('The system')).toBeInTheDocument()
    expect(within(rows[3]).getByRole('group', { name: 'Rhea, root@e2e.local, Root' })).toBeInTheDocument()
    // A live account links to its page in the console.
    expect(within(rows[0]).getAllByRole('link')[0]).toHaveAttribute('href', '/admin/users/mem-a')
    expect(screen.getByText(/never deleted from here/)).toBeInTheDocument()
  })

  test('the act-as and Fireteam tabs show their own columns', async () => {
    h.search = 'table=act_as'
    list = () => json(pageOf([actAs('x1')]))
    renderPage()
    const table = await screen.findByRole('table', { name: 'Act-as rows' })
    expect(within(table).getByText('ticket 42')).toBeInTheDocument()
    expect(within(table).getByText('30 min')).toBeInTheDocument()
    expect(lastList().searchParams.get('table')).toBe('act_as')
    cleanup()
    h.search = 'table=fireteam'
    list = () => json(pageOf([fireteam('f1')]))
    renderPage()
    const ft = await screen.findByRole('table', { name: 'Fireteam settings rows' })
    expect(within(ft).getByText('2 → 4')).toBeInTheDocument()
    expect(within(ft).getByText('fireteamMaxConcurrent')).toBeInTheDocument()
  })
})

describe('filters and tabs', () => {
  test('filters are sent to the API and kept in the address; Clear filters empties both', async () => {
    renderPage()
    await screen.findByText('No row recorded yet.')
    fireEvent.change(screen.getByLabelText('Actor'), { target: { value: 'gone@e2e.local' } })
    fireEvent.change(screen.getByLabelText('Action'), { target: { value: 'project.share.*' } })
    fireEvent.change(screen.getByLabelText('Kind'), { target: { value: 'sharing' } })
    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-11-01' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(lastList().searchParams.get('actor')).toBe('gone@e2e.local'))
    expect(Object.fromEntries(lastList().searchParams)).toEqual({ actor: 'gone@e2e.local', action: 'project.share.*', group: 'sharing', from: '2026-11-01' })
    expect(h.replace).toHaveBeenLastCalledWith('/admin/audit?actor=gone%40e2e.local&action=project.share.*&group=sharing&from=2026-11-01', { scroll: false })
    expect(await screen.findByText('No row matches these filters.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(lastList().search).toBe(''))
    expect(h.replace).toHaveBeenLastCalledWith('/admin/audit', { scroll: false })
  })

  test('the address opens a tab with its filters; a filter the tab does not take is dropped', async () => {
    h.search = 'table=act_as&actor=adm-a&project=proj-1'
    renderPage()
    await waitFor(() => expect(listCalls()).toHaveLength(1))
    expect(Object.fromEntries(lastList().searchParams)).toEqual({ table: 'act_as', actor: 'adm-a' })
    expect(screen.getByRole('tab', { name: 'Act-as' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByLabelText('Project id')).toBeNull()
    expect(screen.getByLabelText('Admin')).toHaveValue('adm-a')
  })

  test('switching tab keeps the filters the new tab takes; arrow keys move between tabs', async () => {
    h.search = 'actor=adm-a&targetType=user'
    renderPage()
    await waitFor(() => expect(listCalls()).toHaveLength(1))
    fireEvent.click(screen.getByRole('tab', { name: 'Fireteam settings' }))
    await waitFor(() => expect(lastList().searchParams.get('table')).toBe('fireteam'))
    expect(Object.fromEntries(lastList().searchParams)).toEqual({ table: 'fireteam', actor: 'adm-a' })
    const fire = screen.getByRole('tab', { name: 'Fireteam settings' })
    expect(fire).toHaveAttribute('tabindex', '0')
    expect(screen.getByRole('tab', { name: 'Audit log' })).toHaveAttribute('tabindex', '-1')
    fireEvent.keyDown(fire, { key: 'ArrowLeft' })
    await waitFor(() => expect(lastList().searchParams.get('table')).toBe('act_as'))
    expect(screen.getByRole('tab', { name: 'Act-as' })).toHaveFocus()
    fireEvent.keyDown(screen.getByRole('tab', { name: 'Act-as' }), { key: 'Home' })
    await waitFor(() => expect(lastList().searchParams.get('table')).toBeNull())
  })
})

describe('pagination', () => {
  test('Load more asks the next page with the cursor and appends it; a failed one says why', async () => {
    list = (url) => (url.searchParams.get('cursor')
      ? json(pageOf([logEntry('r2', { label: 'Second page row' })]))
      : json(pageOf([logEntry('r1', { label: 'First page row' })], { nextCursor: 'CUR1' })))
    renderPage()
    expect(await screen.findByText('First page row')).toBeInTheDocument()
    expect(screen.getByText('Showing 1 row (more below)')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Second page row')).toBeInTheDocument()
    expect(lastList().searchParams.get('cursor')).toBe('CUR1')
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
    cleanup()
    list = (url) => (url.searchParams.get('cursor')
      ? json({ error: 'Could not read the audit log', code: 'P1001' }, 500)
      : json(pageOf([logEntry('r1')], { nextCursor: 'CUR1' })))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Load more' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
  })
})

describe('details', () => {
  test('an audit log row: its facts, then its before and after from the details route (secrets withheld there)', async () => {
    list = () => json(pageOf([logEntry('r1', { permission: 'users:edit' })]))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /^Details: Changed an account/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('users:edit')).toBeInTheDocument()
    expect(await within(dialog).findByText(/Recorded actor email: ada-then@e2e.local/)).toBeInTheDocument()
    expect(within(dialog).getByText(/"tokenPrefix": "\[withheld\]"/)).toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([u]) => String(u))).toContain('/api/admin/audit/r1')
  })

  test('a details read that fails says why and retries', async () => {
    list = () => json(pageOf([logEntry('r1')]))
    let calls = 0
    rowDetail = (id) => (++calls === 1
      ? json({ error: 'Could not read the audit row', code: 'P1001' }, 500)
      : json({ row: { ...logEntry(id), actorEmailRecorded: null, before: null, after: null } }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /^Details:/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('P1001')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Retry' }))
    expect(await within(dialog).findByText(/Recorded actor email: none/)).toBeInTheDocument()
  })

  test('an act-as row shows what the list carries, with no extra read', async () => {
    h.search = 'table=act_as'
    list = () => json(pageOf([actAs('x1', { event: 'end', label: 'Stopped acting as an account', endedBy: 'expiry', reason: null })]))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /^Details: Stopped acting/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('expiry')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([u]) => String(u).startsWith('/api/admin/audit/x1'))).toBe(false)
  })
})

describe('export', () => {
  test('no export without audit:export', async () => {
    renderPage(['audit:read'])
    await screen.findByText('No row recorded yet.')
    expect(screen.queryByRole('button', { name: /^Export/ })).toBeNull()
  })

  test('CSV and JSON download the current filters, named as the server names the file', async () => {
    h.search = 'actor=adm-a'
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    renderPage(['audit:read', 'audit:export'])
    await screen.findByText('No row matches these filters.')
    fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }))
    expect(await screen.findByText('Exported 1 row.')).toBeInTheDocument()
    const exportUrl = new URL(String(fetchMock.mock.calls.find(([u]) => String(u).startsWith('/api/admin/audit/export'))![0]), 'http://redamon.test')
    expect(Object.fromEntries(exportUrl.searchParams)).toEqual({ actor: 'adm-a', format: 'csv' })
    expect(click).toHaveBeenCalledTimes(1)
    expect((click.mock.instances[0] as unknown as HTMLAnchorElement).download).toBe('redamon-audit-audit-20261113T120000Z.csv')
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:audit')
    exportAnswer = () => new Response('{}', { status: 200, headers: { 'x-audit-export-rows': '100000', 'x-audit-export-total': '120000', 'x-audit-export-truncated': 'true' } })
    fireEvent.click(screen.getByRole('button', { name: 'Export JSON' }))
    expect(await screen.findByText('Exported the first 100000 of 120000 rows: narrow the filters to export the rest.')).toBeInTheDocument()
    click.mockRestore()
  })

  test('a refused export opens the app dialog with the reason; nothing is downloaded', async () => {
    exportAnswer = () => json({ error: 'Could not export the audit log', code: 'P1001' }, 500)
    renderPage(['audit:read', 'audit:export'])
    await screen.findByText('No row recorded yet.')
    fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Export failed')).toBeInTheDocument()
    expect(within(dialog).getByText(/P1001/)).toBeInTheDocument()
    expect(URL.createObjectURL).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(screen.getByRole('button', { name: 'Export CSV' })).not.toBeDisabled()
  })
})

describe('states', () => {
  test('loading, then error with Retry', async () => {
    let answer: (r: Response) => void = () => {}
    list = () => new Promise<Response>((resolve) => { answer = resolve })
    renderPage()
    expect(screen.getByRole('status')).toHaveTextContent('Loading the audit rows…')
    answer(json({ error: 'Could not read the audit log', code: 'P1001' }, 500))
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    list = () => json(pageOf([logEntry('r1', { label: 'After retry' })]))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('After retry')).toBeInTheDocument()
  })

  test('denied: a 403 from the route shows the permission it needs', async () => {
    list = () => json({ error: 'Forbidden', code: 'forbidden', permission: 'audit:read' }, 403)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('audit:read')
  })

  test('empty: nothing recorded, or nothing matching', async () => {
    renderPage()
    expect(await screen.findByText('No row recorded yet.')).toBeInTheDocument()
    cleanup()
    h.search = 'action=nothing.here'
    renderPage()
    expect(await screen.findByText('No row matches these filters.')).toBeInTheDocument()
  })
})

describe('labels and keyboard', () => {
  test('tabs, filters, the export group and each Details button are labelled; nothing is taken out of the tab order but inactive tabs', async () => {
    list = () => json(pageOf([logEntry('r1')]))
    const { container } = renderPage(['audit:read', 'audit:export'])
    await screen.findByRole('table', { name: 'Audit log rows' })
    expect(screen.getByRole('tablist', { name: 'Audit tables' })).toBeInTheDocument()
    expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', screen.getByRole('tab', { name: 'Audit log' }).id)
    expect(screen.getByRole('search', { name: 'Filter the Audit log rows' })).toBeInTheDocument()
    for (const label of ['Actor', 'On behalf of', 'Target', 'Target type', 'Project id', 'Action', 'Kind', 'From', 'To']) {
      expect(screen.getByLabelText(label)).toBeInTheDocument()
    }
    expect(screen.getByRole('group', { name: 'Export the rows these filters select' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Details: Changed an account, / })).toBeInTheDocument()
    const untabbable = [...container.querySelectorAll('[tabindex="-1"]')].filter((el) => el.getAttribute('role') !== 'tab')
    expect(untabbable).toEqual([])
  })
})
