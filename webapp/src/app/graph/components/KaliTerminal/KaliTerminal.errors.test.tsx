/**
 * What the Kali terminal prints when it cannot connect (G-16).
 *
 * It printed "Terminal authentication failed (could not obtain a ticket)" for
 * every refused mint and "Disconnected from your Kali sandbox" for every close. It
 * now prints the mint's own refusal with its HTTP status, the update hint only
 * when no ticket secret exists, and the close code and reason the agent wrote.
 *
 * Run: npx vitest run src/app/graph/components/KaliTerminal/KaliTerminal.errors.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, cleanup, waitFor, act } from '@testing-library/react'

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
import { KaliTerminal, disconnectLine, ticketFailureLine } from './KaliTerminal'
import { ApiError } from '@/lib/apiError'

class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  static CONNECTING = 0
  readyState = 0
  binaryType = ''
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onerror: (() => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null
  constructor(public url: string) { FakeSocket.instances.push(this) }
  send() {}
  close() {}
}

const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '')
const lines = () => written.map(plain)

function mint(status: number, body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  })))
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

describe('KaliTerminal connection failures', () => {
  test("a refused mint prints the route's reason and status, and dials nothing", async () => {
    mint(404, { error: 'Not found' })
    render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    await waitFor(() => expect(lines()).toContain('✗ Terminal authentication failed: Not found (HTTP 404)'))
    expect(FakeSocket.instances).toHaveLength(0)
  })

  test('no ticket secret on the webapp prints the update hint', async () => {
    mint(200, { ticket: null })
    render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    await waitFor(() => expect(lines().some(l => l.includes('the webapp issued no ticket (AGENT_WS_TICKET_SECRET is not set)'))).toBe(true))
    expect(FakeSocket.instances).toHaveLength(0)
  })

  test('a close prints the code and the reason the agent wrote', async () => {
    mint(200, { ticket: 'tkt' })
    render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => {
      FakeSocket.instances[0].onclose?.({ code: 1011, reason: 'Kali sandbox terminal unavailable (ConnectionRefusedError)' } as CloseEvent)
    })
    expect(lines()).toContain('\n✗ Disconnected from your Kali sandbox (close 1011: Kali sandbox terminal unavailable (ConnectionRefusedError))')
  })

  test('a socket error names the URL without the ticket', async () => {
    mint(200, { ticket: 'secret-ticket' })
    render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { FakeSocket.instances[0].onerror?.() })
    const line = lines().find(l => l.includes('WebSocket connection to'))
    expect(line).toContain('ws://agent.test/ws/kali-terminal failed')
    expect(line).not.toContain('secret-ticket')
  })
})

describe('KaliTerminal line helpers', () => {
  test('a mint that got no answer says so', () => {
    const line = ticketFailureLine({ ok: false, error: new ApiError({ reason: 'Could not get a ticket for the agent connection', status: 0, code: 'network_error' }) })
    expect(line).toBe('Terminal authentication failed: Could not get a ticket for the agent connection (network_error)')
  })

  test('a usable ticket has no failure line', () => {
    expect(ticketFailureLine({ ok: true, ticket: 't' })).toBeNull()
  })

  test('a bare drop explains the 1006', () => {
    expect(disconnectLine(1006, '')).toBe(
      'Disconnected from your Kali sandbox (close 1006: no answer from the agent (down, restarting, or the handshake was refused))',
    )
  })
})
