/**
 * The projects page's "All projects (oversight)" (step 4.14, SH-47, SH-18): with sharing in force a
 * holder of `projects:oversee` gets a filter listing every project, each card naming its owner and
 * how the admin reaches it (Oversight (Read), Break-glass (Read + Raw data)), opened read only, never
 * deletable; Root gets a break-glass control on someone else's card (reason, duration, password) and
 * closes one that is open. Nobody else sees the filter, and acting as someone hides it.
 *
 * Run: npx vitest run --no-file-parallelism src/app/projects/page.oversight.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within, waitFor } from '@testing-library/react'

const h = vi.hoisted(() => ({
  projects: { data: undefined as unknown, isLoading: false, error: null as unknown, refetch: vi.fn() },
  sharing: { enabled: true, maxLevel: 'read' } as undefined | null | { enabled: boolean; maxLevel: 'read' | 'write' },
  held: new Set<string>(),
  actingAs: null as null | { id: string },
  push: vi.fn(),
  setCurrentProject: vi.fn(),
  confirm: vi.fn(),
  toast: vi.fn(),
  alertError: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: h.push, replace: vi.fn() }) }))
vi.mock('next/link', () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }))
vi.mock('@/hooks/useProjects', () => ({
  useProjects: () => h.projects,
  useDeleteProject: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [], isLoading: false }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.held.has(p), useRbacFlags: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'admin-1', setUserId: vi.fn(), setCurrentProject: h.setCurrentProject }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useOptionalAuth: () => ({
    user: { id: 'admin-1', name: 'Ada', email: 'ada@example.test', role: 'admin', sharing: h.sharing, actingAs: h.actingAs },
  }),
}))
vi.mock('./ImportModal', () => ({ ImportModal: () => null }))
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: h.alertError, dangerConfirm: vi.fn(), confirm: h.confirm }),
  useToast: () => ({ success: h.toast, error: vi.fn() }),
  WikiInfoButton: () => null,
  Modal: ({ isOpen, title, children }: { isOpen: boolean; title: string; children: React.ReactNode }) =>
    (isOpen ? <div role="dialog" aria-label={title}>{children}</div> : null),
}))

import ProjectsPage from './page'

const ADA = { id: 'admin-1', name: 'Ada', email: 'ada@example.test' }
const ALICE = { id: 'alice', name: 'Alice', email: 'alice@example.test' }
const access = (via: string, rawData: boolean, owner: typeof ADA, level = 'read') =>
  ({ level, toggles: { rawData }, via, owner: { name: owner.name, email: owner.email } })
const row = (id: string, name: string, user: typeof ADA, myAccess: Record<string, unknown>) => ({
  id, userId: user.id, name, description: null, targetDomain: `${id}.example.test`,
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', user, myAccess,
})
const OWN = row('p-ada', 'Ada lab', ADA, access('owner', true, ADA, 'owner'))
const OVERSEEN = row('p-alice', 'Alice audit', ALICE, access('oversight', false, ALICE))
const GLASS = row('p-alice-2', 'Alice incident', ALICE, access('break_glass', true, ALICE))

let calls: Array<{ url: string; init?: RequestInit }> = []
let oversightRows: unknown[] = []
let breakGlassAnswer: { status: number; body: unknown } = { status: 201, body: { breakGlass: { id: 'bg1', projectId: 'p-alice', expiresAt: '2026-11-13T13:00:00.000Z', durationMinutes: 60 } } }

const card = (name: string) => screen.getByRole('heading', { name, level: 3 }).closest('.card') as HTMLElement
const filter = () => screen.getByRole('group', { name: 'Show projects' })

async function showOversight() {
  fireEvent.click(within(filter()).getByRole('button', { name: 'All projects (oversight)' }))
  await screen.findByRole('region', { name: 'All projects (oversight)' })
  await screen.findByRole('heading', { name: 'Alice audit', level: 3 })
}

beforeEach(() => {
  vi.clearAllMocks()
  calls = []
  h.projects = { data: [OWN], isLoading: false, error: null, refetch: vi.fn() }
  h.sharing = { enabled: true, maxLevel: 'read' }
  h.held = new Set(['projects:oversee'])
  h.actingAs = null
  h.confirm.mockResolvedValue(true)
  oversightRows = [OWN, OVERSEEN, GLASS]
  breakGlassAnswer = { status: 201, body: { breakGlass: { id: 'bg1', projectId: 'p-alice', expiresAt: '2026-11-13T13:00:00.000Z', durationMinutes: 60 } } }
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url === '/api/projects/oversight') return new Response(JSON.stringify(oversightRows), { status: 200 })
    if (url.endsWith('/breakglass') && init?.method === 'POST') return new Response(JSON.stringify(breakGlassAnswer.body), { status: breakGlassAnswer.status })
    if (url.endsWith('/breakglass') && init?.method === 'DELETE') return new Response(JSON.stringify({ closed: 1 }), { status: 200 })
    return new Response('{}', { status: 404 })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('All projects (oversight)', () => {
  test('a holder gets the filter; nothing is read until it is chosen', async () => {
    render(<ProjectsPage />)
    expect(within(filter()).getByRole('button', { name: 'All projects (oversight)' })).toHaveAttribute('aria-pressed', 'false')
    // Nothing is shared with the admin, so the Shared with me filter is not offered.
    expect(within(filter()).queryByRole('button', { name: 'Shared with me' })).toBeNull()
    expect(calls).toEqual([])
    await showOversight()
    expect(calls.map((c) => c.url)).toEqual(['/api/projects/oversight'])
  })

  test('each card names the owner and how the admin reaches it; read only, never deletable; own project as before', async () => {
    render(<ProjectsPage />)
    await showOversight()
    const region = screen.getByRole('region', { name: 'All projects (oversight)' })
    expect(within(region).getAllByRole('heading', { level: 3 }).map((e) => e.textContent)).toEqual(['Ada lab', 'Alice audit', 'Alice incident'])
    expect(within(card('Alice audit')).getByText('Owner: Alice (alice@example.test)')).toBeInTheDocument()
    expect(within(card('Alice audit')).getByText('Oversight (Read)')).toBeInTheDocument()
    expect(within(card('Alice incident')).getByText('Break-glass (Read + Raw data)')).toBeInTheDocument()
    expect(within(card('Alice audit')).queryByTitle('Delete Project')).toBeNull()
    expect(within(card('Ada lab')).getByTitle('Delete Project')).toBeInTheDocument()
    expect(within(region).getByText(/recorded in its activity, which its owner sees/)).toBeInTheDocument()
    // Without projects:administer: no break-glass control.
    expect(within(card('Alice audit')).queryByRole('button', { name: /break-glass/i })).toBeNull()
  })

  test('opening an overseen project selects it, read only from its own access', async () => {
    render(<ProjectsPage />)
    await showOversight()
    fireEvent.click(card('Alice audit'))
    expect(h.setCurrentProject).toHaveBeenCalledWith(expect.objectContaining({ id: 'p-alice', name: 'Alice audit' }))
    expect(h.push).toHaveBeenCalledWith('/graph?project=p-alice')
  })

  test('a failed list says why and retries', async () => {
    oversightRows = []
    const fetchMock = vi.mocked(fetch)
    fetchMock.mockImplementationOnce(async () => new Response(JSON.stringify({ error: 'boom', code: 'P1001' }), { status: 500 }))
    render(<ProjectsPage />)
    fireEvent.click(within(filter()).getByRole('button', { name: 'All projects (oversight)' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('P1001')
    fireEvent.click(within(alert).getByRole('button', { name: /Retry/ }))
    expect(await screen.findByText('There are no projects on this instance yet.')).toBeInTheDocument()
  })

  test.each([
    ['a member or an admin without projects:oversee', () => { h.held = new Set() }],
    ['sharing not in force', () => { h.sharing = { enabled: false, maxLevel: 'read' } }],
    ['the switch off (no sharing key)', () => { h.sharing = undefined }],
    ['acting as someone', () => { h.actingAs = { id: 'alice' } }],
  ])('%s: no oversight filter, nothing read', async (_what, arrange) => {
    arrange()
    render(<ProjectsPage />)
    expect(screen.queryByRole('button', { name: 'All projects (oversight)' })).toBeNull()
    expect(calls).toEqual([])
  })
})

describe("Root's break-glass from the oversight list", () => {
  beforeEach(() => {
    h.held = new Set(['projects:oversee', 'projects:administer'])
  })

  test('Root opens it with a reason, a duration and its password; the list is read again', async () => {
    render(<ProjectsPage />)
    await showOversight()
    fireEvent.click(within(card('Alice audit')).getByRole('button', { name: 'Open break-glass on Alice audit' }))
    const dialog = screen.getByRole('dialog', { name: 'Break-glass access' })
    expect(dialog).toHaveTextContent('Alice (alice@example.test) will be told')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open break-glass' }))
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Say why')
    fireEvent.change(within(dialog).getByLabelText('Reason (required)'), { target: { value: 'incident 7' } })
    fireEvent.change(within(dialog).getByLabelText('For how long'), { target: { value: '30' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open break-glass' }))
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Enter your password')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open break-glass' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const post = calls.find((c) => c.init?.method === 'POST')!
    expect(post.url).toBe('/api/projects/p-alice/breakglass')
    expect(JSON.parse(String(post.init!.body))).toEqual({ reason: 'incident 7', durationMinutes: 30, stepUpPassword: 'root-pass' })
    expect(h.toast).toHaveBeenCalledWith(expect.stringMatching(/^Break-glass open until /))
    await waitFor(() => expect(calls.filter((c) => c.url === '/api/projects/oversight')).toHaveLength(2))
    expect(h.push).not.toHaveBeenCalled()
  })

  test('a refusal stays in the dialog with its reason and code', async () => {
    breakGlassAnswer = { status: 403, body: { error: 'Password is incorrect', code: 'step_up_failed' } }
    render(<ProjectsPage />)
    await showOversight()
    fireEvent.click(within(card('Alice audit')).getByRole('button', { name: 'Open break-glass on Alice audit' }))
    const dialog = screen.getByRole('dialog', { name: 'Break-glass access' })
    fireEvent.change(within(dialog).getByLabelText('Reason (required)'), { target: { value: 'incident 7' } })
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'wrong' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open break-glass' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('step_up_failed')
  })

  test('an open break-glass is closed after a confirmation, then the list is read again', async () => {
    render(<ProjectsPage />)
    await showOversight()
    fireEvent.click(within(card('Alice incident')).getByRole('button', { name: 'Close break-glass on Alice incident' }))
    await waitFor(() => expect(calls.some((c) => c.init?.method === 'DELETE')).toBe(true))
    expect(h.confirm).toHaveBeenCalledWith(expect.stringContaining('Alice incident'), 'Close break-glass', { confirmLabel: 'Close it' })
    expect(calls.find((c) => c.init?.method === 'DELETE')!.url).toBe('/api/projects/p-alice-2/breakglass')
    expect(h.toast).toHaveBeenCalledWith('Break-glass closed')
  })

  test('cancelling the confirmation closes nothing', async () => {
    h.confirm.mockResolvedValue(false)
    render(<ProjectsPage />)
    await showOversight()
    fireEvent.click(within(card('Alice incident')).getByRole('button', { name: 'Close break-glass on Alice incident' }))
    await waitFor(() => expect(h.confirm).toHaveBeenCalled())
    expect(calls.some((c) => c.init?.method === 'DELETE')).toBe(false)
  })

  test("no break-glass control on Root's own project", async () => {
    render(<ProjectsPage />)
    await showOversight()
    expect(within(card('Ada lab')).queryByRole('button', { name: /break-glass/i })).toBeNull()
  })
})
