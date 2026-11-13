/**
 * The project activity page (step 4.13; UI-08, AU-07, AU-09): who did what on a project, from
 * GET /api/projects/[id]/activity. Loading, error with Retry, denied (403), not available (404) and
 * empty states; each row with its label, time, the actor's identity (name, email, type), the account
 * an admin acted as and the collaborator a share changed; the group filter; Load more, whose failure
 * is told in the app's dialog (useAlertModal).
 *
 * Run: npx vitest run --no-file-parallelism "src/app/projects/[id]/activity/ActivityFeed.test.tsx"
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { ActivityFeed } from './ActivityFeed'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const alice = { name: 'Alice Owner', email: 'alice@example.test', accountType: 'member', deleted: false }
const ada = { name: 'Ada Admin', email: 'ada@example.test', accountType: 'admin', deleted: false }
const bob = { name: 'Bob Reader', email: 'bob@example.test', accountType: 'member', deleted: false }

function event(over: Record<string, unknown>) {
  return {
    id: 'e1', at: '2026-11-13T11:00:00.000Z', action: 'project.update', label: 'Changed the project settings', group: 'project',
    actor: alice, onBehalfOf: null, target: null, source: 'api', ...over,
  }
}

const page = (events: unknown[], over: Record<string, unknown> = {}) =>
  ({ project: { name: 'Acme external' }, events, nextCursor: null, sharesHidden: false, ...over })

const fetchMock = vi.fn()
const urls = () => fetchMock.mock.calls.map(c => String(c[0]))

function renderFeed() {
  return render(<AlertProvider><ActivityFeed projectId="P1" /></AlertProvider>)
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('states', () => {
  test('loading, then the rows', async () => {
    let answer!: (r: Response) => void
    fetchMock.mockReturnValueOnce(new Promise<Response>(r => { answer = r }))
    renderFeed()
    expect(screen.getByRole('status')).toHaveTextContent('Loading the project activity')
    answer(json(page([event({})])))
    expect(await screen.findByText('Changed the project settings')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Activity: Acme external' })).toBeInTheDocument()
    expect(urls()).toEqual(['/api/projects/P1/activity'])
  })

  test('empty: nothing recorded yet', async () => {
    fetchMock.mockResolvedValueOnce(json(page([])))
    renderFeed()
    expect(await screen.findByText('Nothing has been recorded on this project yet.')).toBeInTheDocument()
  })

  test('error with its code and status, and Retry reads again', async () => {
    fetchMock.mockResolvedValueOnce(json({ error: "Could not read the project's activity", code: 'P1001' }, 500))
    fetchMock.mockResolvedValueOnce(json(page([event({})])))
    renderFeed()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('P1001')
    expect(alert).toHaveTextContent('HTTP 500')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Changed the project settings')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  test('denied (403): who can see it, and no Retry', async () => {
    fetchMock.mockResolvedValueOnce(json({ error: 'Forbidden', code: 'forbidden', permission: 'project:share' }, 403))
    renderFeed()
    expect(await screen.findByRole('alert')).toHaveTextContent("Only the project's owner, and admins reading it by oversight, can see its activity.")
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })

  test('not available (404): a project that is gone, not visible, or with sharing off', async () => {
    fetchMock.mockResolvedValueOnce(json({ error: 'Not found' }, 404))
    renderFeed()
    expect(await screen.findByText(/The activity of this project is not available/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Back to projects' })).toHaveAttribute('href', '/projects')
  })
})

describe('rows', () => {
  test('identity: the actor by name, email and account type', async () => {
    fetchMock.mockResolvedValueOnce(json(page([event({ actor: ada })])))
    renderFeed()
    const label = await screen.findByRole('group', { name: 'Ada Admin, ada@example.test, Admin' })
    expect(within(label).getByText('ada@example.test')).toBeInTheDocument()
    expect(within(label).getByText('Admin')).toBeInTheDocument()
  })

  test('acting as: the admin and the account acted as are both named (IM-07)', async () => {
    fetchMock.mockResolvedValueOnce(json(page([event({ actor: ada, onBehalfOf: alice })])))
    renderFeed()
    const item = (await screen.findByText('Changed the project settings')).closest('li')!
    expect(within(item).getByRole('group', { name: 'Ada Admin, ada@example.test, Admin' })).toBeInTheDocument()
    expect(within(item).getByText('acting as')).toBeInTheDocument()
    expect(within(item).getByRole('group', { name: 'Alice Owner, alice@example.test, Member' })).toBeInTheDocument()
  })

  test('a share row names the collaborator; the system, MCP and a deleted account read as such', async () => {
    fetchMock.mockResolvedValueOnce(json(page([
      event({ id: 'e1', action: 'project.share.grant', label: 'Shared the project', group: 'sharing', target: bob }),
      event({ id: 'e2', action: 'project.share.expired', label: 'A share expired', group: 'sharing', actor: null, source: 'system' }),
      event({ id: 'e3', action: 'mcp.list_findings', label: 'MCP tool call: list findings', group: 'mcp', source: 'mcp' }),
      event({ id: 'e4', actor: { name: '', email: 'gone@example.test', accountType: null, deleted: true } }),
      event({ id: 'e5', actor: ada, onBehalfOf: { name: '', email: null, accountType: null, deleted: true } }),
    ])))
    renderFeed()
    const items = await screen.findAllByRole('listitem')
    expect(within(items[0]).getByText('with')).toBeInTheDocument()
    expect(within(items[0]).getByRole('group', { name: 'Bob Reader, bob@example.test, Member' })).toBeInTheDocument()
    expect(items[1]).toHaveTextContent('RedAmon, automatically')
    expect(items[2]).toHaveTextContent('through MCP')
    expect(items[3]).toHaveTextContent('a deleted account (gone@example.test)')
    expect(items[4]).toHaveTextContent('acting as a deleted account')
  })

  test('each row has a machine-readable time', async () => {
    fetchMock.mockResolvedValueOnce(json(page([event({})])))
    const { container } = renderFeed()
    await screen.findByText('Changed the project settings')
    expect(container.querySelector('time')).toHaveAttribute('datetime', '2026-11-13T11:00:00.000Z')
  })

  test("shares hidden by Root's policy: the page says so", async () => {
    fetchMock.mockResolvedValueOnce(json(page([event({})], { sharesHidden: true })))
    renderFeed()
    expect(await screen.findByText(/Share changes are hidden from admins by the instance sharing policy/)).toBeInTheDocument()
  })
})

describe('filter and pages', () => {
  test('the group filter is a labelled select; choosing one reads that group', async () => {
    fetchMock.mockResolvedValueOnce(json(page([event({})])))
    fetchMock.mockResolvedValueOnce(json(page([event({ id: 'e9', action: 'project.share.grant', label: 'Shared the project', group: 'sharing' })])))
    renderFeed()
    await screen.findByText('Changed the project settings')
    const select = screen.getByLabelText('Show')
    expect(within(select).getByRole('option', { name: 'All activity' })).toBeInTheDocument()
    expect(within(select).getByRole('option', { name: 'Sharing' })).toBeInTheDocument()
    fireEvent.change(select, { target: { value: 'sharing' } })
    expect(await screen.findByText('Shared the project')).toBeInTheDocument()
    expect(urls()).toEqual(['/api/projects/P1/activity', '/api/projects/P1/activity?group=sharing'])
  })

  test('Load more reads the next page with the cursor and appends it; the last page has no button', async () => {
    fetchMock.mockResolvedValueOnce(json(page([event({ id: 'e1' })], { nextCursor: 'c-1' })))
    fetchMock.mockResolvedValueOnce(json(page([event({ id: 'e2', label: 'Activated a scan version' })])))
    renderFeed()
    await screen.findByText('Changed the project settings')
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Activated a scan version')).toBeInTheDocument()
    expect(screen.getByText('Changed the project settings')).toBeInTheDocument()
    expect(urls()[1]).toBe('/api/projects/P1/activity?cursor=c-1')
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
  })

  test('a failed Load more is told in the app dialog and keeps the rows shown', async () => {
    fetchMock.mockResolvedValueOnce(json(page([event({})], { nextCursor: 'c-1' })))
    fetchMock.mockResolvedValueOnce(json({ error: "Could not read the project's activity", code: 'P1001' }, 500))
    renderFeed()
    await screen.findByText('Changed the project settings')
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('Could not load more activity')
    expect(dialog).toHaveTextContent('P1001')
    expect(screen.getByText('Changed the project settings')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Load more' })).not.toBeDisabled())
  })
})
