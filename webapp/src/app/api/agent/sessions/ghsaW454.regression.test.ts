/**
 * GHSA-w454-6hwp-fm58, replayed: the reporter's proof of concept against the four
 * shell-session routes. Bob, a standard member, asks for Alice's live session 1 and her
 * handler job 7 by their sequential ids. Up to 7.7.2 each route proxied the id to the
 * agent with the master key: Bob listed Alice's sessions and target, typed `id; hostname`
 * into her meterpreter, and killed her session and job.
 *
 * Now Bob's list holds his own project's rows only (nothing of Alice's, not even a
 * count), and interact / kill / job kill answer 404 before any drive reaches the agent,
 * with no audit row. Alice still drives her own session.
 *
 * The session, the account read, Prisma and agentFetch are mocked; the access rule,
 * sharedToolAccess and the routes are the real ones. The console-side half of the fix
 * (Bob's agent cannot reach the session through `metasploit_console` either) is
 * tests/test_ghsa_w454_msf_project_lease.py.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockRequireSession = vi.fn()
const mockEffectiveUser = vi.fn()
const mockLoadPrincipal = vi.fn()
const mockConversations = vi.fn()
const mockWriteAudit = vi.fn()
const mockAgentFetch = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => mockRequireSession(...a),
  getEffectiveUser: (...a: unknown[]) => mockEffectiveUser(...a),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: (...a: unknown[]) => mockLoadPrincipal(...a),
}))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => mockWriteAudit(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: { findMany: (...a: unknown[]) => mockConversations(...a) },
    auditLog: { findFirst: vi.fn(async () => null) },
  },
}))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
}))

import { GET as listSessions } from './route'
import { POST as interact } from './[id]/interact/route'
import { POST as killSession } from './[id]/kill/route'
import { POST as killJob } from '../jobs/[id]/kill/route'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { setFlagsForTests } from '@/lib/authz/flags'

const NOW = new Date('2026-09-01T00:00:00Z')
const ALICE_TARGET = '198.51.100.23'

function signedIn(id: string) {
  const principal = { id, email: `${id}@x`, role: 'standard', hasPassword: true, createdAt: NOW, legacyGrants: [] }
  mockRequireSession.mockResolvedValue({ userId: id, role: 'standard' })
  mockLoadPrincipal.mockImplementation(async (who: string) => (who === id ? principal : null))
  mockEffectiveUser.mockResolvedValue({ userId: id })
}

/** The agent's whole-instance list: Alice's session 1 and her handler job 7, Bob's session 2. */
const AGENT_LIST = {
  sessions: [
    { id: 1, type: 'meterpreter', info: "Alice's live post-exploitation shell", connection: `172.28.0.2:4444 -> ${ALICE_TARGET}:51000`, target_ip: ALICE_TARGET, chat_session_id: 'chat-alice' },
    { id: 2, type: 'shell', info: '', connection: '172.28.0.2:4445 -> 203.0.113.9:40000', target_ip: '203.0.113.9', chat_session_id: 'chat-bob' },
  ],
  jobs: [{ id: 7, name: 'Exploit: multi/handler', payload: 'linux/x64/meterpreter/reverse_tcp', port: 4444 }],
  non_msf_sessions: [],
  cache_age_seconds: 0.5,
  agent_busy: false,
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const post = (body?: unknown) => new NextRequest('http://x/api', {
  method: 'POST',
  ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
})
const drives = () => mockAgentFetch.mock.calls.map(c => c[0] as string).filter(p => p !== '/sessions')

let warn: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  mockRequireSession.mockReset()
  mockEffectiveUser.mockReset()
  mockLoadPrincipal.mockReset()
  mockConversations.mockReset().mockImplementation(async () => [
    { sessionId: 'chat-alice', projectId: 'project-alice', project: { userId: 'alice' } },
    { sessionId: 'chat-bob', projectId: 'project-bob', project: { userId: 'bob' } },
  ])
  mockWriteAudit.mockReset().mockResolvedValue(undefined)
  mockAgentFetch.mockReset().mockImplementation(async (path: string) => (
    path === '/sessions' ? json(AGENT_LIST) : json({ busy: false, output: 'uid=0(root) alice-target' })
  ))
  resetSharedToolsForTests()
  setFlagsForTests({})
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  warn.mockRestore()
})

describe('GHSA-w454-6hwp-fm58: Bob against Alice by sequential id', () => {
  test("IMPACT 1: Bob's list holds nothing of Alice's", async () => {
    signedIn('bob')
    const res = await listSessions(new NextRequest('http://x/api/agent/sessions'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.sessions.map((s: { id: number }) => s.id)).toEqual([2])
    expect(body.jobs).toEqual([])
    const text = JSON.stringify(body)
    expect(text).not.toContain(ALICE_TARGET)
    expect(text).not.toContain('chat-alice')
    expect(text).not.toContain('project-alice')
  })

  test("IMPACT 2: Bob's command never reaches Alice's session, whatever the id spelling", async () => {
    signedIn('bob')
    for (const id of ['1', '01', '1.0', ' 1', '-1', '%31']) {
      const res = await interact(post({ command: 'id; hostname' }), params(id))
      expect(res.status, `id ${JSON.stringify(id)}`).toBe(404)
    }
    expect(drives()).toEqual([])
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test("BONUS: Bob cannot kill Alice's session or her handler job", async () => {
    signedIn('bob')
    expect((await killSession(post(), params('1'))).status).toBe(404)
    expect((await killJob(post(), params('7'))).status).toBe(404)
    expect(drives()).toEqual([])
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test('CONTROL: Alice still drives her own session, audited without the command', async () => {
    signedIn('alice')
    const res = await interact(post({ command: 'id; hostname' }), params('1'))
    expect(res.status).toBe(200)
    expect(drives()).toEqual(['/sessions/1/interact'])
    const row = mockWriteAudit.mock.calls[0][0]
    expect(row.action).toBe('agent.session_interact')
    expect(JSON.stringify(row)).not.toContain('hostname')
  })

  test('NEGATIVE CONTROL: no session is a 401 and no agent call', async () => {
    const { NextResponse } = await import('next/server')
    mockRequireSession.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await listSessions(new NextRequest('http://x/api/agent/sessions'))).status).toBe(401)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })
})
