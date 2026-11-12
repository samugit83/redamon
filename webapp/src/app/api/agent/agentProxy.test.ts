/**
 * What the agent proxy routes answer when the agent fails.
 *
 * They called `fetch` directly with a default of localhost:8080 (nothing listens
 * there inside the webapp container) and answered `{error: error.message}`,
 * which is undici's "fetch failed", or `{error: <the agent's raw body>}`, which
 * double-wrapped JSON and could carry an exception's text. They now answer a
 * fixed sentence with a code: 503 agent_unreachable / 504 agent_timeout when
 * the agent never answered, the agent's status (5xx as 502) with
 * `upstreamStatus` when it did, and the agent's own sentence only for a 4xx.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const neo4jRun = vi.fn(async () => ({ records: [] }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProjectOrCapability()))
vi.mock('@/lib/access', () => ({
  guardProject: vi.fn(async () => null),
  requireEffectiveUser: vi.fn(async () => ({ userId: 'u1' })),
  requireConversationAccess: vi.fn(async () => ({ conversation: { id: 'c1', userId: 'u1', projectId: 'p1' } })),
}))
// The session, health and tunnel proxies read the session first (HD-10); these tests are about a signed-in account.
vi.mock('@/lib/session', () => ({
  requireSession: async () => ({ userId: 'u1', role: 'standard' }),
  // The session routes also resolve whose projects' sessions are the caller's (HD-01).
  getEffectiveUser: async () => ({ userId: 'u1' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    // The session routes read the account (HD-01): u1 holds every session.
    user: {
      findUnique: vi.fn(async () => ({
        id: 'u1', email: 'u1@x', role: 'user', password: 'h', createdAt: new Date(0), legacyGrants: ['shell_sessions'],
      })),
    },
    conversation: {
      findUnique: vi.fn(async () => ({ sessionId: 's1', userId: 'u1', projectId: 'p1' })),
      findMany: vi.fn(async () => [{ sessionId: 's1', projectId: 'p1', project: { userId: 'u1' } }]),
      delete: vi.fn(async () => ({})),
    },
  },
}))
vi.mock('../graph/neo4j', () => ({
  getGraphSession: () => ({ run: neo4jRun, close: vi.fn(async () => {}) }),
}))

import * as sessions from './sessions/route'
import * as sessionInteract from './sessions/[id]/interact/route'
import * as sessionKill from './sessions/[id]/kill/route'
import * as wsList from './workspace/list/route'
import * as wsPreview from './workspace/preview/route'
import * as wsUpload from './workspace/upload/route'
import * as wsBulkArchive from './workspace/bulk-archive/route'
import * as files from './files/route'
import * as tunnel from './tunnel-status/route'
import * as health from './health/route'
import * as conversation from '../conversations/[id]/route'

const SECRET = 'Traceback: sk-ant-api03-LEAKED at 10.1.2.3'

function refused(): Error {
  const err = new TypeError('fetch failed')
  ;(err as { cause?: unknown }).cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
  return err
}

const jsonResponse = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

let calls: string[]
let answer: (url: string) => Promise<Response>

beforeEach(() => {
  calls = []
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.stubGlobal('fetch', vi.fn(async (url: unknown) => {
    calls.push(String(url))
    return answer(String(url))
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
  neo4jRun.mockReset()
  neo4jRun.mockImplementation(async () => ({ records: [] }))
})

const listReq = () => new NextRequest('http://x/api/agent/workspace/list?projectId=p1&path=.')

// Interact and kill look their target up in the session list first (HD-01). The lookup
// answers, so the error under test is the drive's own.
const SESSION_LIST = {
  sessions: [{ id: 1, chat_session_id: 's1' }, { id: 3, chat_session_id: 's1' }],
  jobs: [],
  non_msf_sessions: [],
}
const drive = (fail: () => Promise<Response>) => async (url: string) =>
  url.endsWith('/sessions') ? jsonResponse(200, SESSION_LIST) : fail()

describe('agent never answered', () => {
  test('refused: 503 agent_unreachable with the errno, never "fetch failed"', async () => {
    answer = async () => { throw refused() }
    const res = await sessions.GET()
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to fetch sessions', code: 'agent_unreachable', cause: 'ECONNREFUSED' })
    expect(JSON.stringify(body)).not.toContain('fetch failed')
  })

  test('timed out: 504 agent_timeout', async () => {
    answer = async () => { throw new DOMException('The operation was aborted due to timeout', 'TimeoutError') }
    const res = await wsList.GET(listReq())
    expect(res.status).toBe(504)
    expect(await res.json()).toMatchObject({ error: 'Failed to list workspace', code: 'agent_timeout' })
  })

  test('the default address is the agent service, not localhost:8080', async () => {
    vi.stubEnv('AGENT_API_URL', '')
    vi.stubEnv('NEXT_PUBLIC_AGENT_API_URL', '')
    answer = async () => jsonResponse(200, { sessions: [] })
    await sessions.GET()
    expect(calls[0]).toBe('http://agent:8080/sessions')
  })
})

describe('agent answered with an error', () => {
  test('a 5xx gets the fixed message, the code and the agent status, not its text', async () => {
    answer = drive(async () => jsonResponse(500, { error: SECRET }))
    const res = await sessionKill.POST(new NextRequest('http://x', { method: 'POST' }), { params: Promise.resolve({ id: '3' }) })
    expect(calls[1]).toMatch(/\/sessions\/3\/kill$/)
    expect(res.status).toBe(502)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to kill session', code: 'agent_error', upstreamStatus: 500 })
    expect(JSON.stringify(body)).not.toContain('LEAKED')
  })

  test("a 4xx keeps the agent's own sentence", async () => {
    answer = async () => jsonResponse(400, { error: 'path escapes workspace: ../etc' })
    const res = await wsList.GET(listReq())
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'path escapes workspace: ../etc', code: 'agent_error', upstreamStatus: 400 })
  })

  test('an upload collision keeps 409 and code exists for the overwrite prompt', async () => {
    answer = async () => jsonResponse(409, { error: 'a.txt already exists in .', code: 'exists' })
    const form = new FormData()
    form.set('projectId', 'p1')
    form.set('file', new File(['x'], 'a.txt'))
    const res = await wsUpload.POST(new NextRequest('http://x', { method: 'POST', body: form }))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'exists', upstreamStatus: 409 })
  })

  test('a proxy error page is not parsed as JSON', async () => {
    answer = async () => new Response('<html>502 Bad Gateway</html>', { status: 502 })
    const res = await wsPreview.GET(new NextRequest('http://x/api/agent/workspace/preview?projectId=p1&path=a'))
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'Failed to preview', code: 'agent_error', upstreamStatus: 502 })
  })

  test('a session manager timeout reaches the terminal as the upstream status', async () => {
    answer = drive(async () => jsonResponse(504, { error: 'Session interaction timeout' }))
    const req = new NextRequest('http://x', { method: 'POST', body: JSON.stringify({ command: 'id' }) })
    const res = await sessionInteract.POST(req, { params: Promise.resolve({ id: '1' }) })
    expect(calls[1]).toMatch(/\/sessions\/1\/interact$/)
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ error: 'Failed to interact with session', upstreamStatus: 504 })
  })

  test('the bulk archive answers JSON, not the raw upstream text', async () => {
    answer = async () => jsonResponse(400, { error: 'not found: gone.txt' })
    const req = new NextRequest('http://x', { method: 'POST', body: JSON.stringify({ projectId: 'p1', paths: ['gone.txt'] }) })
    const res = await wsBulkArchive.POST(req)
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'not found: gone.txt', code: 'agent_error', upstreamStatus: 400 })
  })

  test('the chat file download no longer double-wraps the agent body', async () => {
    answer = async () => new Response('Forbidden: only /tmp/ paths allowed', { status: 403 })
    const res = await files.GET(new NextRequest('http://x/api/agent/files?path=/etc/passwd'))
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: 'Failed to download file', code: 'agent_error', upstreamStatus: 403 })
  })
})

describe('read-only indicators stay quiet', () => {
  test('tunnel status reads an unreachable agent as no tunnel', async () => {
    answer = async () => { throw refused() }
    const res = await tunnel.GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ngrok: { active: false }, chisel: { active: false } })
  })

  test('health keeps its sentence and adds the code', async () => {
    answer = async () => { throw refused() }
    const res = await health.GET()
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body.code).toBe('agent_unreachable')
    expect(body.cause).toBe('ECONNREFUSED')
    expect(body.error).toContain('connection refused')
  })
})

describe('conversation delete reports the cleanup it could not do (G-45)', () => {
  const del = () => conversation.DELETE(new NextRequest('http://x', { method: 'DELETE' }), { params: Promise.resolve({ id: 'c1' }) })

  test('a refused agent stop and a failed graph cleanup come back as warnings', async () => {
    answer = async () => jsonResponse(500, { error: SECRET })
    neo4jRun.mockImplementation(async () => {
      throw Object.assign(new Error(`MATCH (n) ... ${SECRET}`), { code: 'Neo.TransientError.General.DatabaseUnavailable' })
    })
    const res = await del()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({
      success: true,
      warnings: [
        { step: 'agent_stop', code: 'agent_error', status: 500 },
        { step: 'graph_cleanup', code: 'Neo.TransientError.General.DatabaseUnavailable' },
      ],
    })
    expect(JSON.stringify(body)).not.toContain('LEAKED')
  })

  test('an unreachable agent is named in the warning', async () => {
    answer = async () => { throw refused() }
    const body = await (await del()).json()
    expect(body.warnings).toEqual([{ step: 'agent_stop', code: 'agent_unreachable' }])
  })

  test('a clean delete keeps its plain answer', async () => {
    answer = async () => jsonResponse(200, { stopped: true })
    expect(await (await del()).json()).toEqual({ success: true })
  })
})
