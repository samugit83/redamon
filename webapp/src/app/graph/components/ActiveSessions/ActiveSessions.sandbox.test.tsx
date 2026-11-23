/**
 * The Sessions panel across per-user Kali sandboxes (group 1, B.13, TD-11, WI-S16-1/2/3; OQ-G1-9 A).
 *
 * - Rows are keyed by (sandbox, number): two sessions numbered 1 in two sandboxes are two rows, and
 *   a kill, a job stop or a command names the row's own instance.
 * - When the agent names sandboxes that did not answer, the partial-answer line stands above the
 *   list (and above the empty state), never an error page.
 * - From 7 hours without use, the person's own sandbox warns when it will stop, read from
 *   GET /api/agent/sandbox/status (the person and the view are the server's); nothing is asked for
 *   someone without agent:sessions.
 * - The same answer gives the person's own reverse-shell port (FU-24): the port as LPORT, or why
 *   there is none (a full pool, no pool), above the list and the empty state.
 *
 * Run: npx vitest run src/app/graph/components/ActiveSessions/ActiveSessions.sandbox.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import type { RbacFlags } from '@/lib/authz/flags'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))
vi.mock('./SessionTerminal', async (orig) => ({
  ...(await orig<typeof import('./SessionTerminal')>()),
  SessionTerminal: (props: { sessionId: number | null; sessionKey?: string | null; onInteract: (id: number, c: string) => unknown }) => (
    <button type="button" data-testid="terminal" onClick={() => { if (props.sessionId !== null) void props.onInteract(props.sessionId, 'id') }}>
      terminal {props.sessionKey ?? 'none'}
    </button>
  ),
}))

import { ActiveSessions } from './ActiveSessions'

const SESSIONS = [
  { id: 1, sandbox: 'aaaaa1', type: 'shell', info: 'own box', connection: '', target_ip: '', chat_session_id: null },
  { id: 1, sandbox: 'bbbbb1', type: 'meterpreter', info: 'shared box', connection: '', target_ip: '', chat_session_id: null },
] as never[]
const JOBS = [
  { id: 0, sandbox: 'aaaaa1', name: 'handler A', payload: '', port: 0 },
  { id: 0, sandbox: 'bbbbb1', name: 'handler B', payload: '', port: 0 },
] as never[]

let onInteract: ReturnType<typeof vi.fn>
let onKillSession: ReturnType<typeof vi.fn>
let onKillJob: ReturnType<typeof vi.fn>
let status: () => Response | Promise<Response>
let fetchMock: ReturnType<typeof vi.fn>

const json = (body: unknown, code = 200) => new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } })
const STOP_AT = Math.floor(new Date(2026, 10, 21, 22, 5, 0).getTime() / 1000)
const hhmm = (epoch: number) => {
  const d = new Date(epoch * 1000)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

beforeEach(() => {
  onInteract = vi.fn(async () => ({ busy: false, output: 'uid=0' }))
  onKillSession = vi.fn(async () => {})
  onKillJob = vi.fn(async () => {})
  status = () => json({ instances: [{ state: 'running', stop_at: null, stop_reason: null, warn: false }] })
  fetchMock = vi.fn(async (url: string) => (String(url) === '/api/agent/sandbox/status' ? status() : json({}, 404)))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

function panel(over: Record<string, unknown> = {}) {
  return (
    <ActiveSessions
      sessions={SESSIONS} jobs={JOBS} nonMsfSessions={[]} agentBusy={false} isLoading={false} projectId="p1"
      onInteract={onInteract as never} onKillSession={onKillSession as never} onKillJob={onKillJob as never}
      {...over}
    />
  )
}

const statusCalls = () => fetchMock.mock.calls.filter(([u]) => String(u) === '/api/agent/sandbox/status')

describe('rows from two sandboxes with the same number', () => {
  test('both are listed, with no duplicate key', () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(panel())
    expect(screen.getAllByText('#1')).toHaveLength(2)
    expect(screen.getByText('own box')).toBeInTheDocument()
    expect(screen.getByText('shared box')).toBeInTheDocument()
    expect(errors.mock.calls.some(c => String(c[0]).includes('same key'))).toBe(false)
    errors.mockRestore()
  })

  test('each card says its instance; Kill on the second kills (bbbbb1, 1)', async () => {
    render(panel())
    const second = screen.getByText('shared box').closest('[data-session-key]') as HTMLElement
    expect(second).toHaveAttribute('data-session-key', 'bbbbb1:1')
    expect(within(second).getByText('bbbbb1')).toBeInTheDocument()
    fireEvent.click(within(second).getByTitle('Kill session'))
    await waitFor(() => expect(onKillSession).toHaveBeenCalledWith({ id: 1, sandbox: 'bbbbb1' }))
  })

  test('a command goes to the selected row\'s instance, and the terminal follows the selection', async () => {
    render(panel())
    fireEvent.click(screen.getByText('shared box'))
    expect(screen.getByTestId('terminal')).toHaveTextContent('terminal bbbbb1:1')
    fireEvent.click(screen.getByTestId('terminal'))
    await waitFor(() => expect(onInteract).toHaveBeenCalledWith({ id: 1, sandbox: 'bbbbb1' }, 'id'))
    fireEvent.click(screen.getByText('own box'))
    expect(screen.getByTestId('terminal')).toHaveTextContent('terminal aaaaa1:1')
    fireEvent.click(screen.getByTestId('terminal'))
    await waitFor(() => expect(onInteract).toHaveBeenLastCalledWith({ id: 1, sandbox: 'aaaaa1' }, 'id'))
  })

  test('Stop on the second job stops (bbbbb1, 0)', async () => {
    render(panel())
    const jobB = screen.getByText('handler B').closest('[data-session-key]') as HTMLElement
    fireEvent.click(within(jobB).getByTitle('Stop job'))
    await waitFor(() => expect(onKillJob).toHaveBeenCalledWith({ id: 0, sandbox: 'bbbbb1' }))
  })

  test('a row without an instance is sent with its number alone (the drive route refuses it: sandbox_required)', async () => {
    render(panel({ sessions: [{ id: 4, type: 'shell', info: 'legacy', connection: '', target_ip: '', chat_session_id: null }], jobs: [] }))
    fireEvent.click(screen.getByTitle('Kill session'))
    await waitFor(() => expect(onKillSession).toHaveBeenCalledWith({ id: 4, sandbox: null }))
  })
})

describe('the partial-answer line (B.13)', () => {
  test('above the list, in the contract\'s words', () => {
    render(panel({ unavailable: 2 }))
    const line = screen.getByText('2 sandboxes did not answer; their sessions may be out of date or missing')
    expect(line).toBeInTheDocument()
    expect(screen.queryByText(/Could not load sessions/)).toBeNull()
  })

  test('one sandbox: the singular line; above the empty state too', () => {
    render(panel({ sessions: [], jobs: [], unavailable: 1 }))
    expect(screen.getByText('1 sandbox did not answer; its sessions may be out of date or missing')).toBeInTheDocument()
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
  })

  test('none unavailable: no line', () => {
    render(panel({ unavailable: 0 }))
    expect(screen.queryByText(/did not answer/)).toBeNull()
  })
})

describe("the stop warning of the person's own sandbox (OQ-G1-9 A)", () => {
  test('from 7 hours without use: the stop time and how to keep it running', async () => {
    status = () => json({ instances: [{ state: 'running', stop_at: STOP_AT, stop_reason: null, warn: true }] })
    render(panel())
    expect(await screen.findByText(
      `Your Kali sandbox stops at ${hhmm(STOP_AT)} because it has not been used for 7 hours; use it to keep it running`,
    )).toBeInTheDocument()
    expect(statusCalls()[0][1]).toMatchObject({ cache: 'no-store' })
  })

  test('shown above the empty state as well', async () => {
    status = () => json({ instances: [{ state: 'running', stop_at: STOP_AT, stop_reason: null, warn: true }] })
    render(panel({ sessions: [], jobs: [] }))
    expect(await screen.findByText(/Your Kali sandbox stops at/)).toBeInTheDocument()
  })

  test('no warning yet, no sandbox, or a failed read: no banner', async () => {
    for (const answer of [
      () => json({ instances: [{ state: 'running', stop_at: STOP_AT, stop_reason: null, warn: false }] }),
      () => json({ instances: [] }),
      () => json({ error: 'x', code: 'orchestrator_unreachable' }, 503),
      () => { throw new TypeError('Failed to fetch') },
    ]) {
      status = answer
      const { unmount } = render(panel())
      await waitFor(() => expect(statusCalls().length).toBeGreaterThan(0))
      expect(screen.queryByText(/Your Kali sandbox stops at/)).toBeNull()
      unmount()
      fetchMock.mockClear()
    }
  })

  test('without agent:sessions nothing is asked', async () => {
    const flags: RbacFlags = { sharedToolsCompat: false, identity: true, permissions: true, sharing: false, sharingWrite: false, governance: false }
    const value: AuthContextValue = {
      user: { id: 'm1', name: 'Member', email: 'm1@e2e.local', role: 'standard', flags },
      isLoading: false, capabilities: new Set(), flags, sessionError: null,
      login: async () => ({}), logout: async () => {}, refresh: async () => {},
    }
    render(<AuthContext.Provider value={value}>{panel()}</AuthContext.Provider>)
    expect(screen.getByRole('alert')).toHaveTextContent('agent:sessions')
    await new Promise(r => setTimeout(r, 20))
    expect(statusCalls()).toEqual([])
  })
})

describe("the person's own reverse-shell port (FU-24)", () => {
  const withPort = (port: Record<string, unknown>) => () =>
    json({ instances: [{ state: 'running', stop_at: null, stop_reason: null, warn: false, ...port }] })
  const portLine = () => screen.queryByTestId('sessions-reverse-port')

  test('a pool port: "Your reverse-shell port (LPORT): N", above the list', async () => {
    status = withPort({ reverse_port: 31001, reverse_port_state: 'assigned' })
    render(panel())
    expect(await screen.findByText('Your reverse-shell port (LPORT): 31001')).toBeInTheDocument()
  })

  test('a full pool: no port, and why, with the way out; above the empty state too', async () => {
    status = withPort({ reverse_port: 4444, reverse_port_state: 'pool_full' })
    render(panel({ sessions: [], jobs: [] }))
    expect(await screen.findByText('No reverse-shell port: the port pool is full. Use your tunnel or a bind payload')).toBeInTheDocument()
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
    expect(portLine()?.textContent).not.toContain('4444')
  })

  test('no pool: no port, use your tunnel or a bind payload', async () => {
    status = withPort({ reverse_port: 4444, reverse_port_state: 'no_pool' })
    render(panel())
    expect(await screen.findByText('No reverse-shell port: use your tunnel or a bind payload')).toBeInTheDocument()
  })

  test('an orchestrator that sends no state: its pool port is the port, its 4444 is none', async () => {
    status = withPort({ reverse_port: 31002, reverse_port_state: null })
    const { unmount } = render(panel())
    expect(await screen.findByText('Your reverse-shell port (LPORT): 31002')).toBeInTheDocument()
    unmount()
    status = withPort({ reverse_port: 4444 })
    render(panel())
    expect(await screen.findByText('No reverse-shell port: use your tunnel or a bind payload')).toBeInTheDocument()
  })

  test('no sandbox running, or a failed read: no port line', async () => {
    for (const answer of [() => json({ instances: [] }), () => json({ error: 'x', code: 'forbidden' }, 403)]) {
      status = answer
      const { unmount } = render(panel())
      await waitFor(() => expect(statusCalls().length).toBeGreaterThan(0))
      await new Promise(r => setTimeout(r, 10))
      expect(portLine()).toBeNull()
      unmount()
      fetchMock.mockClear()
    }
  })
})
