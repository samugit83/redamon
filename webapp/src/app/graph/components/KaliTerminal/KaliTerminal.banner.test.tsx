/**
 * The Kali terminal opens the person's own Kali sandbox (group 1; HD-04 before it): no banner says
 * the environment is shared, whatever the connection does. It mints a ticket that names the
 * terminal socket, and a refused mint says the terminal is not available instead of
 * "authentication failed".
 *
 * Run: npx vitest run src/app/graph/components/KaliTerminal/KaliTerminal.banner.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, cleanup, waitFor, act } from '@testing-library/react'

const written: string[] = []

vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    open() {}
    loadAddon() {}
    clear() {}
    write() {}
    dispose() {}
    writeln(line: string) { written.push(line) }
    onData() { return { dispose() {} } }
    onBinary() { return { dispose() {} } }
  },
}))
vi.mock('@xterm/addon-fit', () => ({
  FitAddon: class { fit() {} proposeDimensions() { return { rows: 24, cols: 80 } } },
}))
vi.mock('@xterm/addon-web-links', () => ({ WebLinksAddon: class {} }))
vi.mock('@/hooks/agentWsUrl', () => ({
  buildAgentWsUrl: (path: string, ticket?: string) => `ws://agent.test${path}${ticket ? `?ticket=${ticket}` : ''}`,
}))

// The terminal shows the sandbox modal through useAlertModal, so it renders under
// the provider the app shell gives it.
import { AlertProvider } from '@/components/ui'
import * as terminalModule from './KaliTerminal'
import { KaliTerminal, ticketFailureLine } from './KaliTerminal'
import { ApiError } from '@/lib/apiError'

class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  static CONNECTING = 0
  readyState = 0
  binaryType = ''
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onerror: (() => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null
  constructor(public url: string) { FakeSocket.instances.push(this) }
  send(data: string) { this.sent.push(data) }
  close() {}
}

const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '')

let fetchMock: ReturnType<typeof vi.fn>
function mint(status: number, body: unknown) {
  fetchMock = vi.fn(async () => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  }))
  vi.stubGlobal('fetch', fetchMock)
}

beforeEach(() => {
  written.length = 0
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket as unknown as typeof WebSocket)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('KaliTerminal: no shared-environment banner (each person has their own sandbox)', () => {
  test('no banner says other projects\' files are visible, before or after the socket connects', async () => {
    expect('SHARED_ENVIRONMENT_NOTICE' in terminalModule).toBe(false)
    mint(200, { ticket: 'tkt' })
    const { container } = render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    expect(screen.queryByRole('note')).toBeNull()
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { FakeSocket.instances[0].onopen?.() })
    expect(screen.queryByRole('note')).toBeNull()
    expect(container.textContent).not.toMatch(/Shared environment|other projects/)
  })

  test('nor when the terminal is refused', async () => {
    mint(403, { error: 'The Kali terminal is open to administrators and to accounts that kept it at the upgrade.', code: 'forbidden', permission: 'platform:kali_terminal' })
    render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    await waitFor(() => expect(written.some(l => plain(l).includes('Kali terminal is open to administrators'))).toBe(true))
    expect(screen.queryByRole('note')).toBeNull()
  })
})

describe('KaliTerminal ticket', () => {
  test('the ticket it mints names the terminal socket', async () => {
    mint(200, { ticket: 'tkt' })
    render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(init.body))).toMatchObject({ projectId: 'p1', socket: 'kali-terminal' })
  })

  test('the init frame carries no identity: the agent proxy supplies it', async () => {
    mint(200, { ticket: 'tkt' })
    render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { FakeSocket.instances[0].onopen?.() })
    expect(JSON.parse(FakeSocket.instances[0].sent[0])).toEqual({ type: 'init' })
  })

  test('a refused terminal says it is not available, with the route reason', () => {
    const refused = new ApiError({
      reason: 'The Kali terminal is open to administrators and to accounts that kept it at the upgrade.',
      status: 403, code: 'forbidden',
    })
    expect(ticketFailureLine({ ok: false, error: refused })).toBe(
      'Terminal not available: The Kali terminal is open to administrators and to accounts that kept it at the upgrade. (forbidden · HTTP 403)',
    )
  })
})
