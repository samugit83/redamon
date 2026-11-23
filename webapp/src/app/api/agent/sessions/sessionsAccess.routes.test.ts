/**
 * The shell-session routes answer per project (HD-01, HD-02): the list holds what the
 * caller may see; interact and kill re-check the same rule for their target (the agent's
 * list is fetched and the id looked up) and answer 404 for anything else, before the
 * command reaches the session. Each drive writes `agent.session_interact` /
 * `agent.session_kill` / `agent.job_kill` (session id, project id; never the command).
 * Every row carries its Kali sandbox instance and the agent's person tags (group 1, WI-S16-2): a
 * drive names the instance (`?sandbox=`) and is recorded as `<instance>:<number>`; the lists across
 * sandboxes and the naming rules are agentSessionsAccess.sandbox.test.ts.
 *
 * The session, the account read, Prisma, agentFetch and the gateway are mocked; the access rule and
 * sharedToolAccess are the real ones.
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
// The drive's `attempted` row (written before forwarding, in auditedTransaction); mockWriteAudit gets the outcome row.
const mockWriteAuditTx = vi.fn()
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
  writeAuditTx: (...a: unknown[]) => mockWriteAuditTx(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: { findMany: (...a: unknown[]) => mockConversations(...a) },
    $transaction: async (fn: (tx: unknown) => unknown) => fn({}),
    auditLog: { findFirst: vi.fn(async () => null) },
  },
}))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
}))
vi.mock('@/lib/sandbox/gateway', () => ({ sandboxProjectsFor: async () => [] }))

import { GET as listSessions } from './route'
import { POST as interact } from './[id]/interact/route'
import { POST as killSession } from './[id]/kill/route'
import { POST as killJob } from '../jobs/[id]/kill/route'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { setFlagsForTests } from '@/lib/authz/flags'

const NOW = new Date('2026-09-01T00:00:00Z')

function principal(id: string, role = 'standard', legacyGrants: string[] = []) {
  return { id, email: `${id}@x`, role, hasPassword: true, createdAt: NOW, legacyGrants }
}

function signedIn(real: ReturnType<typeof principal>, actingAs?: string) {
  mockRequireSession.mockResolvedValue({ userId: real.id, role: real.role })
  mockLoadPrincipal.mockImplementation(async (id: string) => (id === real.id ? real : null))
  mockEffectiveUser.mockResolvedValue({ userId: actingAs ?? real.id })
}

// member-a's own sandbox is `aaaaa1`, member-b's `bbbbb1`; the agent adds the person tags.
const OWN_A = { sandbox: 'aaaaa1', sandbox_user: 'member-a', sandbox_view: 'own' }
const OWN_B = { sandbox: 'bbbbb1', sandbox_user: 'member-b', sandbox_view: 'own' }
const LIST = {
  sessions: [
    { id: 1, type: 'meterpreter', info: '', connection: '', target_ip: '', chat_session_id: 'chat-a', ...OWN_A },
    { id: 2, type: 'shell', info: '', connection: '', target_ip: '', chat_session_id: 'chat-b', ...OWN_B },
    { id: 3, type: 'shell', info: '', connection: '', target_ip: '', chat_session_id: null, ...OWN_A },
    // A row without its sandbox instance stands for no project and is never a drive target.
    { id: 4, type: 'shell', info: '', connection: '', target_ip: '', chat_session_id: 'chat-a' },
  ],
  jobs: [{ id: 0, name: 'Exploit: multi/handler', payload: 'p', port: 4444, ...OWN_A }],
  non_msf_sessions: [],
  cache_age_seconds: 0.5,
  agent_busy: false,
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

/** The agent: GET /sessions answers LIST; a drive answers its own body. */
function agent(driveBody: unknown = { busy: false, output: 'uid=0(root)' }) {
  mockAgentFetch.mockImplementation(async (path: string) => (path === '/sessions' ? json(LIST) : json(driveBody)))
}

const params = (id: string) => ({ params: Promise.resolve({ id }) })
const post = (body?: unknown, sandbox: string | null = 'aaaaa1') => new NextRequest(`http://x/api${sandbox === null ? '' : `?sandbox=${sandbox}`}`, {
  method: 'POST',
  ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
})
const drives = () => mockAgentFetch.mock.calls.map(c => c[0] as string).filter(p => p !== '/sessions')
const auditRows = () => mockWriteAudit.mock.calls.map(c => c[0])

let warn: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  mockRequireSession.mockReset()
  mockEffectiveUser.mockReset()
  mockLoadPrincipal.mockReset()
  mockConversations.mockReset().mockImplementation(async () => [
    { sessionId: 'chat-a', projectId: 'project-a', userId: 'member-a', project: { userId: 'member-a' } },
    { sessionId: 'chat-b', projectId: 'project-b', userId: 'member-b', project: { userId: 'member-b' } },
  ])
  mockWriteAudit.mockReset().mockResolvedValue(undefined)
  mockWriteAuditTx.mockReset().mockResolvedValue(undefined)
  mockAgentFetch.mockReset()
  resetSharedToolsForTests()
  setFlagsForTests({})
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  warn.mockRestore()
})

describe('GET /api/agent/sessions', () => {
  test("a member gets their own project's sessions and no job", async () => {
    signedIn(principal('member-a'))
    agent()
    const res = await listSessions(new NextRequest('http://x/api/agent/sessions'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.sessions.map((s: { id: number }) => s.id)).toEqual([1])
    expect(body.jobs).toEqual([])
    expect(body).not.toHaveProperty('hidden')
  })

  test('a legacy holder and an admin get every session and job', async () => {
    for (const who of [principal('holder', 'standard', ['shell_sessions']), principal('admin-a', 'admin')]) {
      signedIn(who)
      agent()
      const body = await (await listSessions(new NextRequest('http://x/api/agent/sessions'))).json()
      expect(body.sessions.map((s: { id: number }) => s.id)).toEqual([1, 2, 3, 4])
      expect(body.jobs).toHaveLength(1)
    }
  })

  test('no session: 401 and no agent call', async () => {
    const { NextResponse } = await import('next/server')
    mockRequireSession.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await listSessions(new NextRequest('http://x/api/agent/sessions'))).status).toBe(401)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a failed account read is a coded 500, never a list', async () => {
    mockRequireSession.mockResolvedValue({ userId: 'm', role: 'standard' })
    mockEffectiveUser.mockResolvedValue({ userId: 'm' })
    mockLoadPrincipal.mockRejectedValue(Object.assign(new Error('db down: secret'), { code: 'P1001' }))
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await listSessions(new NextRequest('http://x/api/agent/sessions'))
    err.mockRestore()
    expect(res.status).toBe(500)
    expect(JSON.stringify(await res.json())).not.toContain('secret')
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an agent failure is passed on as before', async () => {
    signedIn(principal('member-a'))
    mockAgentFetch.mockResolvedValue(json({ error: 'Session manager refused the agent\'s credential', code: 'session_manager_unauthorized' }, 502))
    const res = await listSessions(new NextRequest('http://x/api/agent/sessions'))
    expect(res.status).toBe(502)
  })
})

describe('POST /api/agent/sessions/[id]/interact', () => {
  test("a member types into their own project's session; the audit row has no command", async () => {
    signedIn(principal('member-a'))
    agent()
    const res = await interact(post({ command: 'cat /etc/shadow' }), params('1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ busy: false, output: 'uid=0(root)' })
    expect(drives()).toEqual(['/sessions/1/interact?sandbox=aaaaa1'])
    const rows = auditRows()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      actorId: 'member-a', action: 'agent.session_interact', targetType: 'msf_session', targetId: 'aaaaa1:1',
      after: { projectId: 'project-a', via: 'owner', sandbox: 'aaaaa1', sandboxUser: 'member-a' }, source: 'ui',
    })
    expect(JSON.stringify(rows)).not.toContain('shadow')
  })

  test("another project's session, one in another sandbox, or one standing for no project: 404 and nothing typed", async () => {
    signedIn(principal('member-a'))
    agent()
    for (const [id, sandbox] of [['2', 'bbbbb1'], ['2', 'aaaaa1'], ['1', 'bbbbb1'], ['3', 'aaaaa1'], ['99', 'aaaaa1'], ['abc', 'aaaaa1']]) {
      const res = await interact(post({ command: 'id' }, sandbox), params(id))
      expect([id, sandbox, res.status]).toEqual([id, sandbox, 404])
    }
    expect(drives()).toEqual([])
    expect(auditRows()).toEqual([])
  })

  test('the sandbox is always named: without ?sandbox= 400 sandbox_required, `shared` 400 invalid_sandbox, before any agent call', async () => {
    signedIn(principal('admin-a', 'admin'))
    agent()
    const missing = await interact(post({ command: 'id' }, null), params('4'))
    expect(missing.status).toBe(400)
    expect((await missing.json()).code).toBe('sandbox_required')
    const shared = await interact(post({ command: 'id' }, 'shared'), params('4'))
    expect(shared.status).toBe(400)
    expect((await shared.json()).code).toBe('invalid_sandbox')
    expect(mockAgentFetch).not.toHaveBeenCalled()
    expect(auditRows()).toEqual([])
  })

  test('a holder types into any session', async () => {
    signedIn(principal('holder', 'standard', ['shell_sessions']))
    agent()
    expect((await interact(post({ command: 'id' }, 'bbbbb1'), params('2'))).status).toBe(200)
    expect(auditRows()[0]).toMatchObject({ after: { projectId: 'project-b', via: 'legacy', sandbox: 'bbbbb1', sandboxUser: 'member-b' } })
  })

  test("an admin acting as a member is recorded with the member's id", async () => {
    signedIn(principal('admin-a', 'admin'), 'member-a')
    agent()
    expect((await interact(post({ command: 'id' }), params('3'))).status).toBe(200)
    expect(auditRows()[0]).toMatchObject({
      actorId: 'admin-a', after: { projectId: null, via: 'admin', actingAsUserId: 'member-a' },
    })
  })

  test('a body that is not JSON is a 400 before any agent call', async () => {
    signedIn(principal('member-a'))
    agent()
    const res = await interact(new NextRequest('http://x/api', { method: 'POST', body: 'nope' }), params('1'))
    expect(res.status).toBe(400)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a busy console is answered; the attempt is audited and its outcome is busy', async () => {
    // Changed by design (S16b): every forwarded drive has an `attempted` row written before it is
    // sent, and an outcome row; before, a busy answer wrote none.
    signedIn(principal('member-a'))
    agent({ busy: true, message: 'Agent is executing a command, try again shortly' })
    const res = await interact(post({ command: 'id' }), params('1'))
    expect(res.status).toBe(200)
    expect((await res.json()).busy).toBe(true)
    expect(mockWriteAuditTx.mock.calls.map(c => c[1].after.outcome)).toEqual(['attempted'])
    expect(auditRows().map(r => r.after.outcome)).toEqual(['busy'])
  })
})

describe('POST /api/agent/sessions/[id]/kill', () => {
  test('kill of a hidden session 404', async () => {
    signedIn(principal('member-a'))
    agent()
    for (const [id, sandbox] of [['2', 'bbbbb1'], ['3', 'aaaaa1']]) {
      expect((await killSession(post(undefined, sandbox), params(id))).status).toBe(404)
    }
    expect(drives()).toEqual([])
    expect(auditRows()).toEqual([])
  })

  test("a member kills their own project's session", async () => {
    signedIn(principal('member-a'))
    agent({ busy: false, output: 'Killing 1' })
    expect((await killSession(post(), params('1'))).status).toBe(200)
    expect(drives()).toEqual(['/sessions/1/kill?sandbox=aaaaa1'])
    expect(auditRows()[0]).toMatchObject({
      action: 'agent.session_kill', targetType: 'msf_session', targetId: 'aaaaa1:1', after: { projectId: 'project-a', via: 'owner', sandbox: 'aaaaa1' },
    })
  })

  test('the agent unreachable while looking the session up: its answer, no kill', async () => {
    signedIn(principal('member-a'))
    const { AgentUnreachableError } = await import('@/lib/agentFetch')
    mockAgentFetch.mockRejectedValue(new AgentUnreachableError(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })))
    const res = await killSession(post(), params('1'))
    expect(res.status).toBe(503)
    expect(auditRows()).toEqual([])
  })
})

describe('POST /api/agent/jobs/[id]/kill', () => {
  test('jobs hidden for a member: 404, nothing killed', async () => {
    signedIn(principal('member-a'))
    agent()
    expect((await killJob(post(), params('0'))).status).toBe(404)
    expect(drives()).toEqual([])
  })

  test('an admin kills a job', async () => {
    signedIn(principal('admin-a', 'admin'))
    agent({ busy: false, output: 'Stopping job 0' })
    expect((await killJob(post(), params('0'))).status).toBe(200)
    expect(drives()).toEqual(['/jobs/0/kill?sandbox=aaaaa1'])
    expect(auditRows()[0]).toMatchObject({ action: 'agent.job_kill', targetType: 'msf_job', targetId: 'aaaaa1:0', after: { via: 'admin', sandbox: 'aaaaa1' } })
  })
})
