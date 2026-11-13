/**
 * The admin console's Operations section (step 6.5; GV-06, GV-18; DV-06, DV-19, UI-11): the agent runs,
 * running and queued scans, triage runs and shell sessions of every user, each with its project's
 * owner and its actor (and the admin behind an act-as run); read again every 10 seconds, a failed
 * refresh keeping the last lists with a notice; the global emergency stop and a stop per running agent
 * run, offered only when the server says the person may stop runs and each behind the app's danger
 * confirmation (never window.confirm); a source that does not answer named by its code; loading,
 * error + Retry, denied and empty states; labelled controls. The console shell (6.1) denies the page
 * to anyone without platform:operations before it renders.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/operations/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent, act } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AlertProvider } from '@/components/ui'
import type { OperationsView, OpsAgentRun, OpsScan } from '@/lib/authz/adminOperations'

const h = vi.hoisted(() => ({ sections: [] as Array<{ id: string }> }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(''),
  usePathname: () => '/admin/operations',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))
vi.mock('@/app/admin/AdminConsole', () => ({ useConsoleSections: () => h.sections }))

import AdminOperationsPage from './page'

const P1 = { id: 'p-1', name: 'Alpha', owner: { id: 'own-a', name: 'Owner A' } }
const P2 = { id: 'p-2', name: 'Beta', owner: { id: 'own-b', name: 'Owner B' } }

function run(over: Partial<OpsAgentRun> = {}): OpsAgentRun {
  return {
    key: 'mem-b:p-1:s-1', sessionId: 's-1', project: P1, actor: { id: 'mem-b', name: 'Member B' }, realActor: null,
    running: true, connected: true, ...over,
  }
}

function scan(key: string, over: Partial<OpsScan> = {}): OpsScan {
  return {
    key, kind: 'full_recon', status: 'running', source: 'scan', project: P1, actor: { id: 'mem-a', name: 'Member A' },
    detail: '', startedAt: '2026-11-13T11:50:00.000Z', enqueuedAt: '2026-11-13T11:50:00.000Z', blockedCode: '', blockedReason: '', ...over,
  }
}

function opsView(over: Partial<OperationsView> = {}): OperationsView {
  return {
    generatedAt: '2026-11-13T12:00:00.000Z',
    actions: { stopRuns: true },
    agentRuns: { state: { ok: true }, runs: [] },
    scans: { orchestrator: { ok: true }, running: [], queued: [], queuedTotal: 0 },
    triageRuns: [],
    shells: { state: { ok: true }, sessions: [], jobs: 0 },
    ...over,
  }
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let fetchMock: ReturnType<typeof vi.fn>
let viewAnswer: () => Response | Promise<Response>
let stopAnswer: (body: Record<string, unknown>) => Response
let stopAllAnswer: () => Response

beforeEach(() => {
  h.sections = [{ id: 'operations' }, { id: 'users' }]
  viewAnswer = () => json(opsView())
  stopAnswer = () => json({ stopped: true })
  stopAllAnswer = () => json({ scope: 'all', stopped: 3 })
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(String(input), 'http://redamon.test')
    if (url.pathname === '/api/admin/operations') return viewAnswer()
    if (url.pathname === '/api/admin/operations/agent-runs/stop') return stopAnswer(JSON.parse(String(init?.body)))
    if (url.pathname === '/api/agent/emergency-stop-all') return stopAllAnswer()
    return json({}, 404)
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function renderPage() {
  return render(<AlertProvider><AdminOperationsPage /></AlertProvider>)
}

const calls = (path: string) => fetchMock.mock.calls.filter(([u]) => new URL(String(u), 'http://redamon.test').pathname === path)
const tableRow = (table: string, text: string) => within(screen.getByRole('table', { name: table })).getByText(text).closest('tr')!

describe('lists runs with owners and actors', () => {
  test('agent runs, scans, queued scans, triage runs and shells, each with the owner and who runs it', async () => {
    viewAnswer = () => json(opsView({
      agentRuns: { state: { ok: true }, runs: [run({ realActor: { id: 'adm-x', name: 'Admin X' } }), run({ key: 'k2', sessionId: 's-2', project: P2, actor: { id: 'mem-c', name: 'Member C' }, running: false, connected: false })] },
      scans: {
        orchestrator: { ok: true },
        running: [scan('scan:1', { kind: 'partial_recon', detail: 'naabu' }), scan('live:gvm:p-2:', { kind: 'gvm', source: 'live', project: P2, actor: null })],
        queued: [scan('queue:q1', { status: 'queued', source: 'queue', blockedCode: 'ram', blockedReason: 'Waiting for memory', startedAt: null })],
        queuedTotal: 1,
      },
      triageRuns: [{
        id: 't-1', project: P2, actor: { id: 'mem-d', name: 'Member D' }, realActor: null, status: 'running', trigger: 'mcp',
        phase: 'review', progress: 40, startedAt: '2026-11-13T11:58:00.000Z', heartbeatAt: '2026-11-13T11:59:40.000Z',
      }],
      shells: {
        state: { ok: true },
        sessions: [{ key: 'session:3', id: '3', kind: 'session', type: 'meterpreter', project: P1, person: { id: 'mem-a', name: 'Member A' } }],
        jobs: 2,
      },
    }))
    renderPage()
    const first = within((await screen.findAllByText('Member B'))[0].closest('tr')!)
    expect(first.getByText('Alpha')).toBeInTheDocument()
    expect(first.getByRole('link', { name: 'Owner A' })).toHaveAttribute('href', '/admin/users/own-a')
    expect(first.getByRole('link', { name: 'Member B' })).toHaveAttribute('href', '/admin/users/mem-b')
    expect(first.getByText(/acting as them/)).toBeInTheDocument()
    expect(first.getByRole('link', { name: 'Admin X' })).toBeInTheDocument()
    expect(first.getByText('Running')).toBeInTheDocument()
    const idle = within(tableRow('Agent runs', 'Member C'))
    expect(idle.getByText('Idle')).toBeInTheDocument()
    expect(idle.queryByRole('button')).toBeNull()

    expect(within(tableRow('Scans running', 'Partial recon · naabu')).getByText('Member A')).toBeInTheDocument()
    expect(within(tableRow('Scans running', 'GVM')).getByText(/No person/)).toBeInTheDocument()
    expect(within(tableRow('Scans running', 'GVM')).getByText('Owner B')).toBeInTheDocument()
    expect(within(tableRow('Queued scans', 'Waiting for memory')).getByText('Queued')).toBeInTheDocument()
    expect(within(tableRow('Triage runs', 'Member D')).getByText('An MCP client')).toBeInTheDocument()
    expect(within(tableRow('Triage runs', 'Member D')).getByText('review · 40%')).toBeInTheDocument()
    expect(within(tableRow('Shell sessions', 'Session 3 · meterpreter')).getByText('Owner A')).toBeInTheDocument()
    expect(screen.getByText(/2 background jobs/)).toBeInTheDocument()
  })

  test('names are plain text when the Users section is not open to the viewer', async () => {
    h.sections = [{ id: 'operations' }]
    viewAnswer = () => json(opsView({ agentRuns: { state: { ok: true }, runs: [run()] } }))
    renderPage()
    await screen.findByText('Member B')
    expect(screen.queryByRole('link')).toBeNull()
  })

  test('a deleted project and a nameless account still show, by id', async () => {
    viewAnswer = () => json(opsView({ agentRuns: { state: { ok: true }, runs: [run({ project: { id: 'p-gone', name: null, owner: null }, actor: { id: 'u-9', name: null } })] } }))
    renderPage()
    expect(await screen.findByText('Deleted project (p-gone)')).toBeInTheDocument()
    expect(screen.getByText('Account u-9')).toBeInTheDocument()
  })

  test('more queued scans than listed: says how many', async () => {
    viewAnswer = () => json(opsView({ scans: { orchestrator: { ok: true }, running: [], queued: [scan('queue:q1', { status: 'queued' })], queuedTotal: 250 } }))
    renderPage()
    expect(await screen.findByText(/Showing the first 1 of 250/)).toBeInTheDocument()
  })
})

describe('states', () => {
  test('loading first, then every empty state', async () => {
    let release: (r: Response) => void = () => {}
    viewAnswer = () => new Promise<Response>((resolve) => { release = resolve })
    renderPage()
    expect(screen.getByRole('status')).toHaveTextContent('Loading the operations view')
    await act(async () => { release(json(opsView())) })
    expect(await screen.findByText(/No agent session is open/)).toBeInTheDocument()
    expect(screen.getByText('No scan is running.')).toBeInTheDocument()
    expect(screen.getByText('No scan is waiting in the queue.')).toBeInTheDocument()
    expect(screen.getByText('No triage run is in progress.')).toBeInTheDocument()
    expect(screen.getByText('No shell session or listener is open.')).toBeInTheDocument()
  })

  test('denied: the route refuses platform:operations', async () => {
    viewAnswer = () => json({ error: 'You do not hold the permission this action needs (platform:operations).', code: 'forbidden', permission: 'platform:operations' }, 403)
    renderPage()
    expect(await screen.findByText('platform:operations')).toBeInTheDocument()
    expect(screen.queryByRole('table')).toBeNull()
  })

  test('error with its code, and Retry', async () => {
    viewAnswer = () => json({ error: 'Could not load the operations view', code: 'P1001' }, 500)
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    viewAnswer = () => json(opsView())
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No scan is running.')).toBeInTheDocument()
  })

  test('a source that does not answer is named by its code; the other lists still show', async () => {
    viewAnswer = () => json(opsView({
      agentRuns: { state: { ok: false, code: 'agent_route_missing' }, runs: [] },
      scans: { orchestrator: { ok: false, code: 'orchestrator_unreachable' }, running: [scan('scan:1')], queued: [], queuedTotal: 0 },
      shells: { state: { ok: false, code: 'agent_unreachable' }, sessions: [], jobs: 0 },
    }))
    renderPage()
    expect(await screen.findByText('agent_route_missing')).toBeInTheDocument()
    expect(screen.getByText(/rebuild the agent/)).toBeInTheDocument()
    expect(screen.getByText('orchestrator_unreachable')).toBeInTheDocument()
    expect(screen.getByText('agent_unreachable')).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Scans running' })).toBeInTheDocument()
    expect(screen.queryByText(/No agent session is open/)).toBeNull()
  })
})

describe('refreshes every 10 s', () => {
  test('reads again after 10 s; a failed refresh keeps the last lists with a notice; a refusal shows the denied state', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    viewAnswer = () => json(opsView({ agentRuns: { state: { ok: true }, runs: [run()] } }))
    renderPage()
    await screen.findByText('Member B')
    expect(calls('/api/admin/operations')).toHaveLength(1)

    viewAnswer = () => json({ error: 'Could not load the operations view', code: 'P1001' }, 500)
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    await waitFor(() => expect(calls('/api/admin/operations')).toHaveLength(2))
    expect(await screen.findByText(/Could not refresh/)).toHaveTextContent('P1001')
    expect(screen.getByText('Member B')).toBeInTheDocument()

    viewAnswer = () => json({ error: 'x', code: 'forbidden', permission: 'platform:operations' }, 403)
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    await waitFor(() => expect(calls('/api/admin/operations')).toHaveLength(3))
    expect(await screen.findByText('platform:operations')).toBeInTheDocument()
    expect(screen.queryByText('Member B')).toBeNull()
  })

  test('stops reading when the page closes', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { unmount } = renderPage()
    await screen.findByText('No scan is running.')
    unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(calls('/api/admin/operations')).toHaveLength(1)
  })
})

describe('stop one run', () => {
  test('confirmed through the app dialog, the route gets exactly that run, a notice, then the view reads again', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm')
    let sent: Record<string, unknown> | null = null
    stopAnswer = (b) => { sent = b; return json({ stopped: true }) }
    viewAnswer = () => json(opsView({ agentRuns: { state: { ok: true }, runs: [run()] } }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: "Stop Member B's agent run in Alpha" }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent("Member B's agent run in Alpha stops now")
    fireEvent.click(within(dialog).getByRole('button', { name: 'Stop the run' }))
    expect(await screen.findByText("Stopped Member B's agent run in Alpha.")).toBeInTheDocument()
    expect(sent).toEqual({ userId: 'mem-b', projectId: 'p-1', sessionId: 's-1' })
    await waitFor(() => expect(calls('/api/admin/operations')).toHaveLength(2))
    expect(confirmSpy).not.toHaveBeenCalled()
  })

  test('cancelled: nothing is sent', async () => {
    viewAnswer = () => json(opsView({ agentRuns: { state: { ok: true }, runs: [run()] } }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: "Stop Member B's agent run in Alpha" }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(calls('/api/admin/operations/agent-runs/stop')).toHaveLength(0)
  })

  test('a run already over, and a refusal shown in the app dialog with its code', async () => {
    viewAnswer = () => json(opsView({ agentRuns: { state: { ok: true }, runs: [run()] } }))
    stopAnswer = () => json({ stopped: false })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: "Stop Member B's agent run in Alpha" }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Stop the run' }))
    expect(await screen.findByText("Member B's run in Alpha had already ended.")).toBeInTheDocument()

    stopAnswer = () => json({ error: 'You do not hold the permission this action needs (platform:emergency_stop).', code: 'forbidden', permission: 'platform:emergency_stop' }, 403)
    fireEvent.click(await screen.findByRole('button', { name: "Stop Member B's agent run in Alpha" }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Stop the run' }))
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent('forbidden'))
    expect(screen.getByRole('dialog')).toHaveTextContent('Could not stop the run')
  })

  test('without the stop permission: no Stop button and no global stop', async () => {
    viewAnswer = () => json(opsView({ actions: { stopRuns: false }, agentRuns: { state: { ok: true }, runs: [run()] } }))
    renderPage()
    await screen.findByText('Member B')
    expect(screen.queryByRole('button', { name: /Stop/ })).toBeNull()
  })
})

describe('the global emergency stop', () => {
  test('confirmed, it calls the existing emergency stop and says how many runs stopped', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Stop every agent run' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('Every running agent run of every user stops now')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Stop every run' }))
    expect(await screen.findByText('Emergency stop: stopped 3 agent runs.')).toBeInTheDocument()
    expect(calls('/api/agent/emergency-stop-all')[0][1]).toMatchObject({ method: 'POST' })
  })

  test('the permission lost meanwhile: the server stops only the own runs and the page says so', async () => {
    stopAllAnswer = () => json({ scope: 'own', stopped: 1 })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Stop every agent run' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Stop every run' }))
    expect(await screen.findByText(/no longer stop other people's runs: stopped 1 agent run of your own/)).toBeInTheDocument()
  })

  test('a failure shows in the app dialog with its code', async () => {
    stopAllAnswer = () => json({ error: 'Failed to stop agents', code: 'agent_unreachable' }, 503)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Stop every agent run' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Stop every run' }))
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent('agent_unreachable'))
  })
})

describe('keyboard and labels', () => {
  test('labelled tables and section headings, named buttons, nothing taken out of the tab order', async () => {
    viewAnswer = () => json(opsView({
      agentRuns: { state: { ok: true }, runs: [run()] },
      scans: { orchestrator: { ok: true }, running: [scan('scan:1')], queued: [], queuedTotal: 0 },
    }))
    const { container } = renderPage()
    await screen.findByText('Member B')
    for (const name of [/^Agent runs/, /^Scans running/, /^Queued scans/, /^Triage runs/, /^Shell sessions/]) {
      expect(screen.getByRole('heading', { level: 2, name })).toBeInTheDocument()
    }
    expect(screen.getByRole('region', { name: /^Agent runs/ })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Agent runs' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Scans running' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh now' })).toBeInTheDocument()
    for (const button of screen.getAllByRole('button')) expect(button.textContent || button.getAttribute('aria-label')).toBeTruthy()
    expect(container.querySelector('[tabindex="-1"]')).toBeNull()
  })
})
