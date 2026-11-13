import { describe, test, expect, vi, afterEach } from 'vitest'
import { isWsSessionId, mintWsTicket, WS_SESSION_ID_MAX, WS_SOCKETS } from './wsTicket'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('mintWsTicket', () => {
  test('posts the project, the session and the socket, and answers the ticket', async () => {
    const f = vi.fn(async () => json(200, { ticket: 't-1' }))
    vi.stubGlobal('fetch', f)
    expect(await mintWsTicket('p1', 's1', 'kali-terminal')).toEqual({ ok: true, ticket: 't-1' })
    expect(f).toHaveBeenCalledWith('/api/agent/ws-ticket', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ projectId: 'p1', sessionId: 's1', socket: 'kali-terminal' }),
    }))
  })

  test('the four sockets a ticket can name', () => {
    expect([...WS_SOCKETS]).toEqual(['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'])
  })

  test('a deployment without ticket signing answers a null ticket, which is not a failure', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { ticket: null })))
    expect(await mintWsTicket('p1', 's1', 'agent')).toEqual({ ok: true, ticket: null })
  })

  test("a refusal keeps the route's own reason and status", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(409, { error: 'A version activation is in progress for this project.' })))
    const out = await mintWsTicket('p1', 's1', 'agent')
    expect(out.ok).toBe(false)
    if (!out.ok) expect(out.error.message).toBe('A version activation is in progress for this project. (HTTP 409)')
  })

  test('no answer at all is network_error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const out = await mintWsTicket('p1', 's1', 'agent')
    expect(out.ok).toBe(false)
    if (!out.ok) expect(out.error).toMatchObject({ code: 'network_error', status: 0 })
  })
})

describe('isWsSessionId: the one rule for a ticket\'s session id (the mint and the agent\'s writer check)', () => {
  test("the browser's own ids pass, and so does one at the bound", () => {
    for (const id of [
      `session_${'0f'.repeat(16)}`, '3f2c1a9e-8d7b-4c6a-9e5f-1b2c3d4e5f60', 'kali-1763030400000', 'triage-1763030400000',
      'codefix-1763030400000', 'rbac-writers-collab-session', 'x'.repeat(WS_SESSION_ID_MAX),
    ]) expect(isWsSessionId(id), id).toBe(true)
  })

  test('the bound is 200, the writer check\'s own', () => {
    expect(WS_SESSION_ID_MAX).toBe(200)
  })

  test('refused: empty, over the bound, not a string, or carrying a control character or line separator', () => {
    for (const id of [
      '', 'x'.repeat(WS_SESSION_ID_MAX + 1), 7, null, undefined, ['s'], { s: 1 },
      's\n[rbac] forged', 's\r', 'tab\there', 'nul\u0000', 'del\u007f', 'nel\u0085', 'ls\u2028', 'ps\u2029',
    ]) expect(isWsSessionId(id), JSON.stringify(id)).toBe(false)
  })
})
