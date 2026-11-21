/**
 * The Kali terminal and the person's own sandbox (group 1, WI-S15-4, B.13): the
 * agent proxy sends `sandbox_status` text frames before the PTY starts or instead
 * of it. `starting` shows a banner; `unavailable` shows the modal (Retry
 * reconnects); close 1013 says the sandbox could not start; after a `refused`
 * frame the 1008 close never reconnects by itself. PTY output is binary, so
 * nothing a shell prints can raise the modal.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/KaliTerminal/KaliTerminal.sandbox.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { render, screen, cleanup, waitFor, act, fireEvent, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { MODAL_RAM_TITLE, MODAL_REFUSED_TITLE, MODAL_RETRY_LABEL } from '@/lib/sandbox/contract'

const written: string[] = []
const output: string[] = []

vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    open() {}
    loadAddon() {}
    clear() {}
    write(data: string | Uint8Array) { output.push(typeof data === 'string' ? data : new TextDecoder().decode(data)) }
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

import { KaliTerminal } from './KaliTerminal'
import {
  TERMINAL_CLOSE_REFUSED,
  TERMINAL_CLOSE_UNAVAILABLE,
  TERMINAL_STARTING_BANNER,
  parseSandboxFrame,
  sandboxCloseLine,
} from './sandboxFrames'

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
  close() { this.readyState = 3 }
}

const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '')
const lines = () => written.map(plain)
const reconnecting = () => lines().some(l => l.includes('Reconnecting in'))

const RAM_FRAME = JSON.stringify({
  type: 'sandbox_status', state: 'unavailable', reason: 'ram',
  limit: { admitted: false, limitType: 'ram', resource: 'kali_sandbox', current: 1024 ** 3, ceiling: 8 * 1024 ** 3,
    settingName: null, detail: 'not enough free memory to start a Kali sandbox now' },
})
const REFUSED_FRAME = JSON.stringify({ type: 'sandbox_status', state: 'unavailable', reason: 'refused' })
const STARTING_FRAME = JSON.stringify({ type: 'sandbox_status', state: 'starting' })

function mintOk() {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ticket: 'tkt' }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  })))
}

async function openTerminal() {
  mintOk()
  render(<AlertProvider><KaliTerminal userId="u1" projectId="p1" /></AlertProvider>)
  await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
  const ws = FakeSocket.instances[0]
  act(() => { ws.readyState = 1; ws.onopen?.() })
  return ws
}

const frame = (ws: FakeSocket, data: string | ArrayBuffer) => act(() => { ws.onmessage?.({ data } as MessageEvent) })
const close = (ws: FakeSocket, code: number, reason = '') => act(() => { ws.readyState = 3; ws.onclose?.({ code, reason } as CloseEvent) })
const bytes = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer

beforeEach(() => {
  written.length = 0
  output.length = 0
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket as unknown as typeof WebSocket)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('the starting banner', () => {
  test('a starting frame shows it, and is not written to the terminal', async () => {
    const ws = await openTerminal()
    frame(ws, STARTING_FRAME)
    expect(screen.getByRole('status').textContent).toBe(TERMINAL_STARTING_BANNER)
    expect(output.join('')).not.toContain('sandbox_status')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('the first PTY output clears it and is written', async () => {
    const ws = await openTerminal()
    frame(ws, STARTING_FRAME)
    frame(ws, bytes('root@kali-sandbox:~# '))
    expect(screen.queryByRole('status')).toBeNull()
    expect(output.join('')).toContain('root@kali-sandbox:~# ')
  })

  test('a ready frame clears it', async () => {
    const ws = await openTerminal()
    frame(ws, STARTING_FRAME)
    frame(ws, JSON.stringify({ type: 'sandbox_status', state: 'ready' }))
    expect(screen.queryByRole('status')).toBeNull()
  })
})

describe('a sandbox that cannot start', () => {
  test('ram: the modal; close 1013 says the sandbox could not start and does not reconnect by itself', async () => {
    const ws = await openTerminal()
    frame(ws, STARTING_FRAME)
    frame(ws, RAM_FRAME)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(MODAL_RAM_TITLE)).toBeInTheDocument()
    expect(screen.queryByRole('status')).toBeNull()
    close(ws, 1013, 'Kali sandbox unavailable')
    expect(lines().some(l => l.includes('The Kali sandbox could not start (close 1013: Kali sandbox unavailable)'))).toBe(true)
    expect(reconnecting()).toBe(false)
  })

  test('Retry reconnects', async () => {
    const ws = await openTerminal()
    frame(ws, RAM_FRAME)
    close(ws, 1013)
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: MODAL_RETRY_LABEL }))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
  })

  test('Close does not reconnect', async () => {
    const ws = await openTerminal()
    frame(ws, RAM_FRAME)
    close(ws, 1013)
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await new Promise(r => setTimeout(r, 400))
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('refused: the refused modal with no Retry; close 1008 never reconnects', async () => {
    const ws = await openTerminal()
    frame(ws, REFUSED_FRAME)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(MODAL_REFUSED_TITLE)).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: MODAL_RETRY_LABEL })).toBeNull()
    close(ws, 1008, 'Kali sandbox refused')
    expect(reconnecting()).toBe(false)
    expect(lines().some(l => l.includes('Kali sandbox not available'))).toBe(true)
    fireEvent.click(within(dialog).getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await new Promise(r => setTimeout(r, 400))
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('one modal per connection, however many frames', async () => {
    const ws = await openTerminal()
    frame(ws, RAM_FRAME)
    frame(ws, RAM_FRAME)
    const dialog = await screen.findByRole('dialog')
    // The alert queue shows one dialog at a time: a second one would follow the first.
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await new Promise(r => setTimeout(r, 50))
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('what stays as it was', () => {
  test('a 1013 with no frame before it keeps the usual line and reconnects as before', async () => {
    const ws = await openTerminal()
    close(ws, 1013, 'Max terminal sessions reached')
    expect(lines()).toContain('\n✗ Disconnected from kali-sandbox (close 1013: Max terminal sessions reached)')
    expect(lines().some(l => l.includes('could not start'))).toBe(false)
    expect(reconnecting()).toBe(true)
  })

  test('a close other than 1013 or 1008 after an unavailable frame keeps the usual line, and does not reconnect', async () => {
    const ws = await openTerminal()
    frame(ws, RAM_FRAME)
    close(ws, 1011, 'Kali sandbox terminal unavailable (ConnectionRefusedError)')
    expect(lines()).toContain('\n✗ Disconnected from kali-sandbox (close 1011: Kali sandbox terminal unavailable (ConnectionRefusedError))')
    expect(reconnecting()).toBe(false)
  })

  test('a 1008 with no refused frame (a refused ticket) reconnects as before', async () => {
    const ws = await openTerminal()
    close(ws, 1008, 'Invalid or missing ticket')
    expect(lines()).toContain('\n✗ Disconnected from kali-sandbox (close 1008: Invalid or missing ticket)')
    expect(reconnecting()).toBe(true)
  })

  test('a text frame that is not a status frame is written as before', async () => {
    const ws = await openTerminal()
    frame(ws, 'plain text from the proxy')
    expect(output).toContain('plain text from the proxy')
  })

  test('PTY output that looks like a status frame is written, never obeyed', async () => {
    const ws = await openTerminal()
    frame(ws, bytes(RAM_FRAME))
    expect(output.join('')).toContain('"sandbox_status"')
    await new Promise(r => setTimeout(r, 50))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('once the PTY has spoken, a text status frame is written, never obeyed', async () => {
    const ws = await openTerminal()
    frame(ws, bytes('$ '))
    frame(ws, RAM_FRAME)
    expect(output).toContain(RAM_FRAME)
    await new Promise(r => setTimeout(r, 50))
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('parseSandboxFrame', () => {
  test('only a JSON object of type sandbox_status with a known state', () => {
    expect(parseSandboxFrame(STARTING_FRAME)).toEqual({ state: 'starting' })
    expect(parseSandboxFrame(REFUSED_FRAME)).toMatchObject({ state: 'unavailable', reason: 'refused' })
    expect(parseSandboxFrame(JSON.stringify({ type: 'sandbox_status', state: 'running' }))).toBeNull()
    expect(parseSandboxFrame(JSON.stringify({ type: 'pong' }))).toBeNull()
    expect(parseSandboxFrame('{not json')).toBeNull()
    expect(parseSandboxFrame('ls -la')).toBeNull()
    expect(parseSandboxFrame(`{"type":"sandbox_status","state":"starting","pad":"${'x'.repeat(10_000)}"}`)).toBeNull()
  })
})

const CONTRACT_PY = join(__dirname, '../../../../../../agentic/sandbox_contract.py')

describe('sandboxCloseLine', () => {
  test('a code names the sandbox only after an unavailable frame', () => {
    expect(sandboxCloseLine(1013, '', 'ram')).toBe('The Kali sandbox could not start (close 1013)')
    expect(sandboxCloseLine(1013, 'x', 'error')).toBe('The Kali sandbox could not start (close 1013: x)')
    expect(sandboxCloseLine(1008, 'no', 'refused')).toBe('Kali sandbox not available on this project (close 1008: no)')
    expect(sandboxCloseLine(1013, 'busy', null)).toBeNull()
    expect(sandboxCloseLine(1008, 'Invalid or missing ticket', null)).toBeNull()
    expect(sandboxCloseLine(1008, '', 'ram')).toBeNull()
  })
})

describe('the close codes are the contract', () => {
  test.skipIf(!existsSync(CONTRACT_PY))("they equal agentic/sandbox_contract.py's TERMINAL_CLOSE_UNAVAILABLE and TERMINAL_CLOSE_REFUSED", () => {
    const py = readFileSync(CONTRACT_PY, 'utf8')
    expect(py).toMatch(new RegExp(`^TERMINAL_CLOSE_UNAVAILABLE = ${TERMINAL_CLOSE_UNAVAILABLE}$`, 'm'))
    expect(py).toMatch(new RegExp(`^TERMINAL_CLOSE_REFUSED = ${TERMINAL_CLOSE_REFUSED}$`, 'm'))
  })
})
