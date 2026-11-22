/**
 * Unit tests for the agent WebSocket connection lifecycle.
 *
 * Issue #173 (second symptom): the agent FAILS CLOSED on the init frame and
 * closes the socket with 1008 when the ws-ticket is missing or does not verify
 * (agentic/websocket_api.py). The hook treated that like any other drop and
 * reconnected, so a stack whose .env predates AGENT_WS_TICKET_SECRET showed
 * "Connecting..." forever with nothing to act on. A 1008 must stop the loop and
 * name the cause.
 *
 * Run: npx vitest run src/hooks/useAgentWebSocket.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'
import { ConnectionStatus } from '@/lib/websocket-types'

vi.mock('./agentWsUrl', () => ({ buildAgentWsUrl: () => 'ws://agent.test/ws/agent?probe=1' }))

import { useAgentWebSocket } from './useAgentWebSocket'

// Minimal WebSocket stand-in: records what was sent and lets a test drive the
// close event with a specific code.
class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  readyState = 1
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null

  constructor(public url: string) {
    FakeSocket.instances.push(this)
  }
  send(data: string) { this.sent.push(data) }
  closed = false
  close() { this.closed = true /* the hook detaches handlers before calling this */ }
  fireClose(code: number, reason = '') { this.onclose?.({ code, reason, wasClean: false } as CloseEvent) }
}

const config = {
  userId: 'u1',
  projectId: 'p1',
  sessionId: 's1',
  maxReconnectAttempts: 5,
  reconnectInterval: 10,
}

beforeEach(() => {
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket as unknown as typeof WebSocket)
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    json: async () => ({ ticket: 'tkt' }),
  }) as unknown as Response))
})
afterEach(() => { vi.unstubAllGlobals() })

describe('useAgentWebSocket auth rejection (#173)', () => {
  test('close 1008 → FAILED with an actionable error, and NO reconnect', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]

    await act(async () => { sock.onopen?.() })
    act(() => { sock.fireClose(1008) })

    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toContain('authentication failed')

    // The reconnect timer must never fire for a configuration failure.
    await new Promise(r => setTimeout(r, 60))
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('a ticketless init names the missing secret in the error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ ticket: null }),
    }) as unknown as Response))

    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]

    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(sock.sent).toHaveLength(1))
    act(() => { sock.fireClose(1008) })

    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toContain('AGENT_WS_TICKET_SECRET')
  })

  test('an ordinary drop (1006) still reconnects', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))

    await act(async () => { FakeSocket.instances[0].onopen?.() })
    act(() => { FakeSocket.instances[0].fireClose(1006) })

    expect(result.current.status).toBe(ConnectionStatus.RECONNECTING)
    await waitFor(() => expect(FakeSocket.instances.length).toBeGreaterThan(1))
  })
})

// ---------------------------------------------------------------------------
// "Agent stuck" incident: Stop clicks that vanished while the socket was down,
// a half-open socket nobody noticed, and reconnects that dropped a live run.
// ---------------------------------------------------------------------------

function deliver(sock: FakeSocket, type: string, payload: Record<string, unknown> = {}) {
  sock.onmessage?.({ data: JSON.stringify({ type, payload, timestamp: 't' }) } as MessageEvent)
}
const sentTypes = (sock: FakeSocket) => sock.sent.map(s => JSON.parse(s).type)

async function openAndConnect(sock: FakeSocket, payload: Record<string, unknown> = {}) {
  await act(async () => { sock.onopen?.() })
  act(() => deliver(sock, 'connected', payload))
}

describe('useAgentWebSocket outbox', () => {
  test('Stop and guidance sent while not connected go out right after CONNECTED', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]
    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(sentTypes(sock)).toEqual(['init']))

    act(() => { result.current.sendGuidance('is it running?'); result.current.sendStop() })
    expect(sentTypes(sock)).toEqual(['init'])   // not authenticated yet: held, not dropped

    act(() => deliver(sock, 'connected', { agent_running: true }))
    expect(sentTypes(sock)).toEqual(['init', 'guidance', 'stop'])
  })

  test('a Stop clicked during a drop is delivered on the new connection', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0])
    act(() => { FakeSocket.instances[0].fireClose(1006) })

    act(() => { result.current.sendStop() })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const next = FakeSocket.instances[1]
    await openAndConnect(next)
    expect(sentTypes(next)).toContain('stop')
  })

  test('queries are never queued: a stale question must not replay later', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { result.current.sendQuery('old question') })
    await openAndConnect(FakeSocket.instances[0])
    expect(sentTypes(FakeSocket.instances[0])).not.toContain('query')
  })
})

describe('useAgentWebSocket connection truth', () => {
  test('onConnect receives the server payload with agent_running', async () => {
    const onConnect = vi.fn()
    renderHook(() => useAgentWebSocket({ ...config, onConnect }))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0], { agent_running: false, session_id: 's1' })
    expect(onConnect).toHaveBeenCalledWith(expect.objectContaining({ agent_running: false }))
  })

  test('a half-open socket (pings, no pongs) is replaced instead of freezing the page', async () => {
    vi.useFakeTimers()
    try {
      renderHook(() => useAgentWebSocket(config))
      expect(FakeSocket.instances).toHaveLength(1)
      const sock = FakeSocket.instances[0]
      await openAndConnect(sock)

      act(() => { vi.advanceTimersByTime(30_000) })
      expect(sentTypes(sock).at(-1)).toBe('ping')
      act(() => deliver(sock, 'pong'))
      act(() => { vi.advanceTimersByTime(60_000) })   // 60s since the last pong: still fine
      expect(FakeSocket.instances).toHaveLength(1)

      act(() => { vi.advanceTimersByTime(30_000) })   // 90s without a pong
      expect(sock.closed).toBe(true)
      act(() => { vi.advanceTimersByTime(config.reconnectInterval) })   // through the reconnect backoff
      expect(FakeSocket.instances).toHaveLength(2)
    } finally {
      vi.useRealTimers()
    }
  })

  test('a socket that keeps answering is never replaced', async () => {
    vi.useFakeTimers()
    try {
      renderHook(() => useAgentWebSocket(config))
      const sock = FakeSocket.instances[0]
      await openAndConnect(sock)
      for (let i = 0; i < 10; i++) {
        act(() => { vi.advanceTimersByTime(30_000) })
        act(() => deliver(sock, 'pong'))
      }
      expect(FakeSocket.instances).toHaveLength(1)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('useAgentWebSocket graph-view changes', () => {
  test('a view change during a run waits for the run to end, then reconnects with it', async () => {
    const { rerender } = renderHook(
      (p: { graphViewCypher: string; runActive: boolean }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { graphViewCypher: 'MATCH (a) RETURN a', runActive: true } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0])

    rerender({ graphViewCypher: 'MATCH (b) RETURN b', runActive: true })
    await new Promise(r => setTimeout(r, 30))
    expect(FakeSocket.instances).toHaveLength(1)   // the live run keeps its stream

    rerender({ graphViewCypher: 'MATCH (b) RETURN b', runActive: false })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const next = FakeSocket.instances[1]
    await act(async () => { next.onopen?.() })
    await waitFor(() => expect(next.sent).toHaveLength(1))
    expect(JSON.parse(next.sent[0]).payload.graph_view_cypher).toBe('MATCH (b) RETURN b')
  })

  test('with no run going, a view change reconnects at once', async () => {
    const { rerender } = renderHook(
      (p: { graphViewCypher: string }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { graphViewCypher: 'A' } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await openAndConnect(FakeSocket.instances[0])
    rerender({ graphViewCypher: 'B' })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
  })
})

describe('useAgentWebSocket outbox is per session', () => {
  test('a Stop queued for one session never reaches the session the page switched to', async () => {
    const { result, rerender } = renderHook(
      (p: { sessionId: string }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { sessionId: 's1' } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { result.current.sendStop() })          // s1 not connected yet: queued
    rerender({ sessionId: 's2' })                      // operator opens another session
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const s2 = FakeSocket.instances[1]
    await openAndConnect(s2)
    expect(sentTypes(s2)).not.toContain('stop')
  })
})

// ---------------------------------------------------------------------------
// G-1 / G-2 / G-43: the drawer is told why the socket is not connected.
// ---------------------------------------------------------------------------

function stubMint(status: number, body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  })))
}

describe('useAgentWebSocket says why it is not connected', () => {
  // A hook left mounted keeps reconnecting into the next test's sockets.
  afterEach(() => { cleanup() })

  test('a refused ticket mint stops with its own reason, not the auth hint, and sends no init', async () => {
    stubMint(409, { error: 'A version activation is in progress for this project - the graph is being swapped. Try again once it finishes.' })
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]
    await act(async () => { sock.onopen?.() })

    await waitFor(() => expect(result.current.status).toBe(ConnectionStatus.FAILED))
    expect(result.current.error?.message).toBe(
      'Could not get a ticket for the agent connection: A version activation is in progress for this project - the graph is being swapped. Try again once it finishes. (HTTP 409)',
    )
    expect(result.current.error?.message).not.toContain('redamon.sh update')
    expect(sock.sent).toHaveLength(0)
    expect(sock.closed).toBe(true)
    await new Promise(r => setTimeout(r, 40))
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('an expired session at mint time says 401', async () => {
    stubMint(401, { error: 'Unauthorized' })
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await act(async () => { FakeSocket.instances[0].onopen?.() })
    await waitFor(() => expect(result.current.error?.message).toBe(
      'Could not get a ticket for the agent connection: Unauthorized (HTTP 401)',
    ))
  })

  test('the update hint appears only when a ticket secret is really missing', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]
    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(sock.sent).toHaveLength(1))   // a ticket was minted and sent
    act(() => { sock.fireClose(1008, 'Invalid or missing ticket') })
    expect(result.current.error?.message).toContain('the agent rejected the session ticket (close 1008: Invalid or missing ticket)')
    expect(result.current.error?.message).not.toContain('redamon.sh update')
  })

  test('an agent without the secret says so, with the update hint', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]
    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(sock.sent).toHaveLength(1))
    act(() => { sock.fireClose(1008, 'ticket auth not configured') })
    expect(result.current.error?.message).toBe(
      'Agent WebSocket authentication failed: the agent has no AGENT_WS_TICKET_SECRET. Run ./redamon.sh update, then restart the agent.',
    )
  })

  test('the close code and reason are kept while reconnecting, and the URL has no query', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    expect(result.current.url).toBe('ws://agent.test/ws/agent')
    act(() => { FakeSocket.instances[0].fireClose(1011, 'Orchestrator not initialized') })
    expect(result.current.status).toBe(ConnectionStatus.RECONNECTING)
    expect(result.current.lastClose).toEqual({ code: 1011, reason: 'Orchestrator not initialized' })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    expect(result.current.lastClose).toEqual({ code: 1011, reason: 'Orchestrator not initialized' })
  })

  test('giving up names the last close and the URL', async () => {
    const { result } = renderHook(() => useAgentWebSocket({ ...config, maxReconnectAttempts: 1 }))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { FakeSocket.instances[0].fireClose(1013, 'Server busy (low memory) - retry shortly') })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    act(() => { FakeSocket.instances[1].fireClose(1013, 'Server busy (low memory) - retry shortly') })
    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toBe(
      'Max reconnection attempts reached (last close 1013: Server busy (low memory) - retry shortly) · ws://agent.test/ws/agent',
    )
  })

  test('a connect clears the kept close', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { FakeSocket.instances[0].fireClose(1006) })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    await openAndConnect(FakeSocket.instances[1])
    expect(result.current.lastClose).toBeNull()
  })

  test('decisions report whether they were sent instead of vanishing', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    let sent: boolean[] = []
    act(() => {
      sent = [
        result.current.sendApproval('approve'),
        result.current.sendAnswer('yes'),
        result.current.sendToolConfirmation('approve'),
        result.current.sendFireteamMemberConfirmation('w', 'm', 'approve'),
      ]
    })
    expect(sent).toEqual([false, false, false, false])
    await openAndConnect(FakeSocket.instances[0])
    // Not queued: nothing replays after the connect.
    expect(sentTypes(FakeSocket.instances[0])).toEqual(['init'])
    act(() => { sent = [result.current.sendApproval('approve')] })
    expect(sent).toEqual([true])
    expect(sentTypes(FakeSocket.instances[0])).toEqual(['init', 'approval'])
  })
})

// ---------------------------------------------------------------------------
// The ticket mint between a socket's open and its init. A mint can get no
// answer at all, whatever the cause (Chromium aborts every request in flight
// with net::ERR_NETWORK_CHANGED when a host address appears or goes away, so on
// a Docker host a container on a bridge network starting or stopping can do
// it); and a mint can answer after its socket was replaced.
// ---------------------------------------------------------------------------

const JSON_HEADERS = { 'Content-Type': 'application/json' }
const ticketFor = (id: string) => new Response(JSON.stringify({ ticket: `tkt-${id}` }), { status: 200, headers: JSON_HEADERS })
const inits = (sock: FakeSocket) => sock.sent.map(s => JSON.parse(s)).filter(m => m.type === 'init').map(m => m.payload)
const mintedSession = (init: unknown) => JSON.parse(String((init as RequestInit).body)).sessionId as string

/** A fetch that holds every mint until the test answers or fails it, in call order. */
function holdMints() {
  const mints: { sessionId: string; answer: (res: Response) => void; fail: (err: unknown) => void }[] = []
  vi.stubGlobal('fetch', vi.fn((_url: unknown, init: unknown) => new Promise<Response>((resolve, reject) => {
    mints.push({ sessionId: mintedSession(init), answer: resolve, fail: reject })
  })))
  return mints
}

describe('useAgentWebSocket ticket mint with no answer', () => {
  afterEach(() => { cleanup() })

  test.each([
    ['the browser aborted it (TypeError: Failed to fetch)', new TypeError('Failed to fetch')],
    ['it was cancelled (AbortError)', new DOMException('The operation was aborted.', 'AbortError')],
    ['it timed out (TimeoutError)', new DOMException('The operation timed out.', 'TimeoutError')],
  ])('a mint that got no answer because %s is retried on a new socket, and the drawer connects', async (_why, failure) => {
    let calls = 0
    vi.stubGlobal('fetch', vi.fn(async () => {
      calls += 1
      if (calls === 1) throw failure
      return ticketFor('s1')
    }))
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const first = FakeSocket.instances[0]
    await act(async () => { first.onopen?.() })

    await waitFor(() => expect(result.current.reconnectAttempt).toBe(1))
    expect(first.closed).toBe(true)
    expect(first.sent).toHaveLength(0)
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const second = FakeSocket.instances[1]
    await act(async () => { second.onopen?.() })
    await waitFor(() => expect(inits(second)).toHaveLength(1))
    expect(inits(second)[0]).toMatchObject({ session_id: 's1', ticket: 'tkt-s1' })

    act(() => deliver(second, 'connected'))
    expect(result.current.status).toBe(ConnectionStatus.CONNECTED)
    expect(result.current.error).toBeNull()
    expect(result.current.reconnectAttempt).toBe(0)
  })

  test('mints that never get an answer stop at the attempt cap and name the mint', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const { result } = renderHook(() => useAgentWebSocket({ ...config, maxReconnectAttempts: 2 }))
    for (let n = 1; n <= 3; n++) {
      await waitFor(() => expect(FakeSocket.instances).toHaveLength(n))
      await act(async () => { FakeSocket.instances[n - 1].onopen?.() })
    }
    await waitFor(() => expect(result.current.status).toBe(ConnectionStatus.FAILED))
    expect(result.current.error?.message).toBe(
      'Max reconnection attempts reached (last ticket mint: no answer from the webapp, network_error) · ws://agent.test/ws/agent',
    )
    await new Promise(r => setTimeout(r, 60))
    expect(FakeSocket.instances).toHaveLength(3)
    expect(FakeSocket.instances.every(s => s.sent.length === 0)).toBe(true)
  })

  test.each([
    [404, { error: 'Not found' }, 'Could not get a ticket for the agent connection: Not found (HTTP 404)'],
    [503, { error: 'This use of the project owner\'s credentials could not be recorded, so no connection was opened. Try again.', code: 'spend_not_recorded' },
      'Could not get a ticket for the agent connection: This use of the project owner\'s credentials could not be recorded, so no connection was opened. Try again. (spend_not_recorded · HTTP 503)'],
  ])('a mint the server refused (%i) is never retried: FAILED with its reason', async (status, body, text) => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(body), { status, headers: JSON_HEADERS }))
    vi.stubGlobal('fetch', fetchMock)
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await act(async () => { FakeSocket.instances[0].onopen?.() })

    await waitFor(() => expect(result.current.status).toBe(ConnectionStatus.FAILED))
    expect(result.current.error?.message).toBe(text)
    await new Promise(r => setTimeout(r, 60))
    expect(FakeSocket.instances).toHaveLength(1)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result.current.reconnectAttempt).toBe(0)
  })
})

describe('useAgentWebSocket a mint that answers after its socket was replaced', () => {
  afterEach(() => { cleanup() })

  test('a slow mint of the old session answering after "Start new session" sends nothing: the new session\'s init is the only one', async () => {
    const mints = holdMints()
    const { result, rerender } = renderHook(
      (p: { sessionId: string }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { sessionId: 's1' } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const old = FakeSocket.instances[0]
    await act(async () => { old.onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(1))

    rerender({ sessionId: 's2' })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const next = FakeSocket.instances[1]
    await act(async () => { next.onopen?.() })
    await waitFor(() => expect(mints.map(m => m.sessionId)).toEqual(['s1', 's2']))

    await act(async () => { mints[1].answer(ticketFor('s2')) })
    await waitFor(() => expect(inits(next)).toHaveLength(1))
    act(() => deliver(next, 'connected', { session_id: 's2' }))

    await act(async () => { mints[0].answer(ticketFor('s1')) })
    await new Promise(r => setTimeout(r, 30))

    expect(inits(next)).toEqual([expect.objectContaining({ session_id: 's2', ticket: 'tkt-s2' })])
    expect(inits(old)).toEqual([])
    expect(result.current.status).toBe(ConnectionStatus.CONNECTED)
  })

  test('the old session\'s mint answering first, before the new socket\'s own, sends nothing either', async () => {
    const mints = holdMints()
    const { rerender } = renderHook(
      (p: { sessionId: string }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { sessionId: 's1' } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await act(async () => { FakeSocket.instances[0].onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(1))

    rerender({ sessionId: 's2' })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const next = FakeSocket.instances[1]
    await act(async () => { next.onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(2))

    await act(async () => { mints[0].answer(ticketFor('s1')) })
    await new Promise(r => setTimeout(r, 30))
    expect(inits(next)).toEqual([])

    await act(async () => { mints[1].answer(ticketFor('s2')) })
    await waitFor(() => expect(inits(next)).toHaveLength(1))
    expect(inits(next)[0]).toMatchObject({ session_id: 's2', ticket: 'tkt-s2' })
  })

  test('a mint of a socket that dropped and was replaced sends no second init on the new socket', async () => {
    const mints = holdMints()
    renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const first = FakeSocket.instances[0]
    await act(async () => { first.onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(1))

    act(() => { first.fireClose(1006) })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const second = FakeSocket.instances[1]
    await act(async () => { second.onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(2))
    await act(async () => { mints[1].answer(ticketFor('second')) })
    await waitFor(() => expect(inits(second)).toHaveLength(1))

    await act(async () => { mints[0].answer(ticketFor('first')) })
    await new Promise(r => setTimeout(r, 30))
    expect(inits(second)).toEqual([expect.objectContaining({ ticket: 'tkt-second' })])
  })

  test('the old session\'s mint failing with no answer leaves the new socket alone: no retry, no failure', async () => {
    const mints = holdMints()
    const { result, rerender } = renderHook(
      (p: { sessionId: string }) => useAgentWebSocket({ ...config, ...p }),
      { initialProps: { sessionId: 's1' } },
    )
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await act(async () => { FakeSocket.instances[0].onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(1))

    rerender({ sessionId: 's2' })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    const next = FakeSocket.instances[1]
    await act(async () => { next.onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(2))

    await act(async () => { mints[0].fail(new TypeError('Failed to fetch')) })
    await new Promise(r => setTimeout(r, 60))
    expect(next.closed).toBe(false)
    expect(FakeSocket.instances).toHaveLength(2)
    expect(result.current.reconnectAttempt).toBe(0)
    expect(result.current.status).toBe(ConnectionStatus.CONNECTING)

    await act(async () => { mints[1].answer(ticketFor('s2')) })
    await waitFor(() => expect(inits(next)).toHaveLength(1))
    act(() => deliver(next, 'connected'))
    expect(result.current.status).toBe(ConnectionStatus.CONNECTED)
  })
})

describe('useAgentWebSocket a mint whose answer is not a ticket', () => {
  afterEach(() => { cleanup() })

  test('a 200 whose body was lost after the headers is retried, never a ticketless init with the update hint', async () => {
    let calls = 0
    vi.stubGlobal('fetch', vi.fn(async () => {
      calls += 1
      if (calls === 1) return { ok: true, status: 200, json: async () => { throw new TypeError('network error') } } as unknown as Response
      return ticketFor('s1')
    }))
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const first = FakeSocket.instances[0]
    await act(async () => { first.onopen?.() })

    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    expect(first.sent).toHaveLength(0)
    const second = FakeSocket.instances[1]
    await act(async () => { second.onopen?.() })
    await waitFor(() => expect(inits(second)).toHaveLength(1))
    expect(inits(second)[0]).toMatchObject({ ticket: 'tkt-s1' })
    act(() => deliver(second, 'connected'))
    expect(result.current.status).toBe(ConnectionStatus.CONNECTED)
  })

  test('a 2xx answer that is not JSON stops with its code: no init, no retry', async () => {
    const fetchMock = vi.fn(async () => new Response('<html>Sign in to the network</html>', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await act(async () => { FakeSocket.instances[0].onopen?.() })

    await waitFor(() => expect(result.current.status).toBe(ConnectionStatus.FAILED))
    expect(result.current.error?.message).toBe('Could not get a ticket for the agent connection (invalid_json · HTTP 200)')
    expect(FakeSocket.instances[0].sent).toHaveLength(0)
    await new Promise(r => setTimeout(r, 60))
    expect(FakeSocket.instances).toHaveLength(1)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('useAgentWebSocket after unmount', () => {
  afterEach(() => { cleanup() })

  test('a mint answering after unmount sends nothing, even on a socket that still reads OPEN', async () => {
    const mints = holdMints()
    const { unmount } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]
    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(1))

    unmount()
    await act(async () => { mints[0].answer(ticketFor('s1')) })
    await new Promise(r => setTimeout(r, 30))
    expect(sock.sent).toEqual([])
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('a mint with no answer after unmount, on the last attempt, reports nothing', async () => {
    const mints = holdMints()
    const onError = vi.fn()
    const { unmount } = renderHook(() => useAgentWebSocket({ ...config, maxReconnectAttempts: 0, onError }))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    await act(async () => { FakeSocket.instances[0].onopen?.() })
    await waitFor(() => expect(mints).toHaveLength(1))

    unmount()
    await act(async () => { mints[0].fail(new TypeError('Failed to fetch')) })
    await new Promise(r => setTimeout(r, 60))
    expect(onError).not.toHaveBeenCalled()
    expect(FakeSocket.instances).toHaveLength(1)
  })
})

describe('useAgentWebSocket attempt cap', () => {
  afterEach(() => { cleanup(); vi.useRealTimers() })

  test('a socket that connected on the last allowed attempt is still retried when it drops later', async () => {
    const { result } = renderHook(() => useAgentWebSocket({ ...config, maxReconnectAttempts: 1 }))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    act(() => { FakeSocket.instances[0].fireClose(1006) })
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2))
    await openAndConnect(FakeSocket.instances[1])
    expect(result.current.reconnectAttempt).toBe(0)

    act(() => { FakeSocket.instances[1].fireClose(1006) })
    expect(result.current.status).toBe(ConnectionStatus.RECONNECTING)
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(3))
  })

  /** Connect the first socket with fake timers on, its mint answering at once. */
  async function connectedUnderFakeTimers(sock: FakeSocket) {
    await act(async () => { sock.onopen?.(); await vi.advanceTimersByTimeAsync(1) })
    act(() => deliver(sock, 'connected'))
  }

  test('pong timeouts count as attempts: with mints that never answer, a tab does not keep minting', async () => {
    vi.useFakeTimers()
    let mints = 0
    vi.stubGlobal('fetch', vi.fn(() => {
      mints += 1
      return mints === 1 ? Promise.resolve(ticketFor('s1')) : new Promise<Response>(() => {})
    }))
    const { result } = renderHook(() => useAgentWebSocket(config))
    const first = FakeSocket.instances[0]
    await connectedUnderFakeTimers(first)
    expect(result.current.status).toBe(ConnectionStatus.CONNECTED)

    for (let t = 0; t < 20; t++) {   // 10 minutes, never a PONG
      await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
      const last = FakeSocket.instances.at(-1)!
      if (last !== first && last.onopen) await act(async () => { last.onopen?.(); last.onopen = null; await vi.advanceTimersByTimeAsync(1) })
    }
    expect(first.closed).toBe(true)
    expect(FakeSocket.instances).toHaveLength(2)
    expect(mints).toBe(2)
    expect(result.current.reconnectAttempt).toBe(1)
  })

  test('a pong timeout with no attempt left fails and names the pings', async () => {
    vi.useFakeTimers()
    const { result } = renderHook(() => useAgentWebSocket({ ...config, maxReconnectAttempts: 0 }))
    await connectedUnderFakeTimers(FakeSocket.instances[0])
    await act(async () => { await vi.advanceTimersByTimeAsync(120_000) })
    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toBe('Max reconnection attempts reached (last no answer to pings for 75 s) · ws://agent.test/ws/agent')
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('a socket that connected on the last allowed attempt is still replaced at its pong timeout', async () => {
    vi.useFakeTimers()
    const { result } = renderHook(() => useAgentWebSocket({ ...config, maxReconnectAttempts: 1 }))
    act(() => { FakeSocket.instances[0].fireClose(1006) })
    await act(async () => { await vi.advanceTimersByTimeAsync(config.reconnectInterval) })
    expect(FakeSocket.instances).toHaveLength(2)
    await connectedUnderFakeTimers(FakeSocket.instances[1])
    expect(result.current.reconnectAttempt).toBe(0)

    await act(async () => { await vi.advanceTimersByTimeAsync(90_000 + config.reconnectInterval) })
    expect(result.current.status).not.toBe(ConnectionStatus.FAILED)
    expect(FakeSocket.instances).toHaveLength(3)
  })
})
