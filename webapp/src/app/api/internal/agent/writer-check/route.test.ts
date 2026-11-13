/**
 * POST /api/internal/agent/writer-check (step 5.11 follow-up; SH-40, OQ-35): before every agent run
 * starts on an open socket (a message, an approval, an answer, a tool confirmation, a resume) the
 * agent asks whether another person is writing the project now. The answer is the chat ticket's:
 * 200 `{allowed: true}`, or 409 `{error, code: 'project_writer_busy', busy}` naming who holds it. The
 * owner is read from the database, never taken from the agent; the person is the ticket's `sub`.
 * Only with sharing in force (DV-30: otherwise nothing is read); an unreadable source lets the owner
 * through and refuses anyone else.
 *
 * Real projectWriters, sharing policy reader, flags and Root reader; Prisma, the orchestrator's
 * active-scan list and the agent's live-session authors are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const KEY = 'internal-key-for-test'
vi.stubEnv('INTERNAL_API_KEY', KEY)
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

const h = vi.hoisted(() => ({
  scans: [] as Array<Record<string, unknown>>,
  authors: [] as string[],
  triage: [] as Array<Record<string, unknown>>,
  policy: { enabled: true } as Record<string, unknown>,
  orchestrator: vi.fn(),
  agentAuthors: vi.fn(),
  projectRead: vi.fn(),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestrator(...a) }))
vi.mock('@/lib/agentSessions', () => ({ runningSessionAuthors: (...a: unknown[]) => h.agentAuthors(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectRead(...a) },
    triageRun: { findMany: async () => h.triage, updateMany: async () => ({ count: 0 }) },
    nodeFilterRun: { findMany: async () => [] },
    instanceSettings: {
      findUnique: async () => ({ sharingPolicy: h.policy, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }),
    },
    user: {
      findMany: async ({ where }: { where: { id: { in: string[] } } }) => where.id.in
        .filter(id => id !== 'gone')
        .map(id => ({ id, name: id[0].toUpperCase() + id.slice(1), email: `${id}@example.test`, role: 'standard' })),
    },
  },
}))

import { POST } from './route'
import { secondWriterResponse } from '@/lib/authz/projectWriters'
import { setFlagsForTests, type RbacFlags } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { WS_SESSION_ID_MAX } from '@/lib/wsTicket'

const PATH = '/api/internal/agent/writer-check'
const SHARING: Partial<RbacFlags> = { identity: true, permissions: true, sharing: true }

function req(body: unknown, headers: Record<string, string> = { 'x-internal-key': KEY }): NextRequest {
  return new NextRequest(`http://localhost:3000${PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}
const check = (over: Record<string, unknown> = {}) => ({ userId: 'bob', projectId: 'P-alice', sessionId: 'sess-bob', ...over })
const ask = async (body: unknown, headers?: Record<string, string>) => {
  const res = await POST(req(body, headers))
  return [res.status, await res.json()] as const
}
const scan = (kind: string, actor: string | null) => ({ kind, project_id: 'P-alice', status: 'running', actor_user_id: actor })
const BUSY_TAIL = ' on this project. One person writes a project at a time: wait for it to finish, or ask them to stop it.'

beforeEach(() => {
  h.scans = []
  h.authors = []
  h.triage = []
  h.policy = { enabled: true }
  h.orchestrator.mockReset()
  h.orchestrator.mockImplementation(async () => ({ ok: true, status: 200, json: async () => ({ scans: h.scans }) }))
  h.agentAuthors.mockReset()
  h.agentAuthors.mockImplementation(async () => ({ userIds: [...h.authors] }))
  h.projectRead.mockReset()
  h.projectRead.mockImplementation(async ({ where }: { where: { id: string } }) => (where.id === 'P-alice' ? { userId: 'alice' } : null))
  setFlagsForTests(SHARING)
  clearSharingPolicyCacheForTests()
  clearInstanceRootCacheForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('who may call it', () => {
  test('without the internal key: 401, and nothing about the project is read', async () => {
    for (const headers of [{}, { 'x-internal-key': 'wrong' }] as Array<Record<string, string>>) {
      const [status] = await ask(check(), headers)
      expect(status).toBe(401)
    }
    expect(h.projectRead).not.toHaveBeenCalled()
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test('a malformed check: 400 invalid_writer_check, nothing read', async () => {
    for (const body of ['not json', null, [], {}, check({ userId: '' }), check({ projectId: 7 }), check({ sessionId: 'x'.repeat(201) }),
      check({ actorId: 3 }), check({ userId: undefined })]) {
      const [status, json] = await ask(body)
      expect([status, json.code]).toEqual([400, 'invalid_writer_check'])
    }
    expect(h.projectRead).not.toHaveBeenCalled()
  })

  test("the session id is the ticket's, under the mint's own rule: over the bound or with a control character, 400", async () => {
    for (const sessionId of ['s'.repeat(WS_SESSION_ID_MAX + 1), 'sess\n[rbac] forged', 'sess\r', 'nul\u0000', 'ls\u2028']) {
      const [status, json] = await ask(check({ sessionId }))
      expect([status, json.code]).toEqual([400, 'invalid_writer_check'])
    }
    expect(h.projectRead).not.toHaveBeenCalled()
    expect(await ask(check({ sessionId: 's'.repeat(WS_SESSION_ID_MAX) }))).toEqual([200, { allowed: true }])
  })
})

describe('the log line', () => {
  test('a client value cannot forge a line: no CR/LF reaches the refusal line, and it is bounded', async () => {
    h.scans = [scan('partial_recon', 'alice')]
    const forged = 'admin-1\r\n[rbac] agent run allowed session=x'
    expect((await ask(check({ actorId: forged })))[0]).toBe(409)
    const line = vi.mocked(console.warn).mock.calls.map(c => String(c[0])).find(l => l.startsWith('[rbac] agent run refused'))
    expect(line).toBe('[rbac] agent run refused code=project_writer_busy session=sess-bob actor=admin-1??[rbac] agent run allowed session=x')
    expect(line).not.toMatch(/[\r\n]/)
  })
})

describe('a second writer, asked per run (step 5.11 follow-up)', () => {
  test("a collaborator's socket opened before the owner's partial recon: its next run is refused, naming the owner", async () => {
    h.scans = [scan('partial_recon', 'alice')]
    const [status, json] = await ask(check())
    expect(status).toBe(409)
    expect(json).toEqual({
      code: 'project_writer_busy',
      busy: 'Alice (alice@example.test) is running a partial recon',
      error: `Alice (alice@example.test) is running a partial recon${BUSY_TAIL}`,
    })
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('[rbac] agent run refused code=project_writer_busy session=sess-bob'))
  })

  test("the owner is refused while a collaborator's agent session writes (the risk is the overlap, not who came first)", async () => {
    h.authors = ['bob']
    const [status, json] = await ask(check({ userId: 'alice', sessionId: 'sess-alice' }))
    expect([status, json.busy]).toEqual([409, 'Bob (bob@example.test) is running an agent session'])
  })

  test('another person\'s triage run refuses it too', async () => {
    h.triage = [{ id: 't1', status: 'running', startedAt: new Date(), heartbeatAt: new Date(), actorUserId: 'carol' }]
    const [status, json] = await ask(check())
    expect([status, json.busy]).toEqual([409, 'Carol (carol@example.test) is running a triage run'])
  })

  test('the same person can run two things as today: their own scan and their own sessions refuse nothing', async () => {
    h.scans = [scan('full_recon', 'alice'), scan('gvm', null)]
    h.authors = ['alice']
    expect(await ask(check({ userId: 'alice' }))).toEqual([200, { allowed: true }])
    h.scans = [scan('partial_recon', 'bob')]
    h.authors = ['bob']
    expect(await ask(check())).toEqual([200, { allowed: true }])
  })

  test('the owner comes from the database: a check naming someone else as owner cannot make the agent\'s person the owner', async () => {
    h.scans = [scan('partial_recon', 'alice')]
    const [status] = await ask({ ...check(), ownerId: 'bob', tenantId: 'bob' })
    expect(status).toBe(409)
    expect(h.projectRead).toHaveBeenCalledWith(expect.objectContaining({ where: { id: 'P-alice' } }))
  })

  test('under act-as the person is the account acted as: an admin acting as the owner is the owner', async () => {
    h.scans = [scan('partial_recon', 'alice')]
    expect(await ask(check({ userId: 'alice', actorId: 'admin-1' }))).toEqual([200, { allowed: true }])
    h.scans = [scan('partial_recon', 'bob')]
    const [status, json] = await ask(check({ userId: 'alice', actorId: 'admin-1' }))
    expect([status, json.code]).toEqual([409, 'project_writer_busy'])
  })

  test('once the other writer ends, the run starts', async () => {
    h.scans = [scan('partial_recon', 'alice')]
    expect((await ask(check()))[0]).toBe(409)
    h.scans = [{ ...scan('partial_recon', 'alice'), status: 'completed' }]
    expect(await ask(check())).toEqual([200, { allowed: true }])
  })

  test('a holder whose account was deleted is named as such', async () => {
    h.scans = [scan('partial_recon', 'gone')]
    const [, json] = await ask(check())
    expect(json.busy).toBe('a deleted account is running a partial recon')
  })

  test('a project that no longer exists refuses nothing (no writer to meet; access is the socket\'s own checks)', async () => {
    h.scans = [{ ...scan('partial_recon', 'alice'), project_id: 'P-gone' }]
    expect(await ask(check({ projectId: 'P-gone' }))).toEqual([200, { allowed: true }])
  })

  test('the same body the chat ticket answers for the same state (one payload for both refusals)', async () => {
    h.scans = [scan('trufflehog', 'alice')]
    const [status, json] = await ask(check())
    const direct = await secondWriterResponse({ projectId: 'P-alice', personId: 'bob' })
    expect([status, json]).toEqual([direct!.status, await direct!.json()])
  })
})

describe('a source that cannot be read', () => {
  test("the orchestrator down: the owner's run goes ahead with a log line; a collaborator's is refused (fail closed)", async () => {
    h.orchestrator.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }))
    expect(await ask(check({ userId: 'alice' }))).toEqual([200, { allowed: true }])
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('[rbac] project_writer_unverified project=P-alice person=alice'))
    const [status, json] = await ask(check())
    expect(status).toBe(409)
    expect(json).toEqual({
      code: 'project_writer_busy',
      busy: 'whether someone else is writing this project could not be verified (scans)',
      error: 'Nothing was started: whether someone else is writing this project could not be verified (scans). Try again shortly.',
    })
  })

  test("the agent's own session list unreadable: the same rule", async () => {
    h.agentAuthors.mockResolvedValue({ failure: { code: 'agent_timeout' } })
    expect(await ask(check({ userId: 'alice' }))).toEqual([200, { allowed: true }])
    expect((await ask(check()))[1].busy).toContain('could not be verified (agent)')
  })

  test('the database down for the owner read: a coded 500, which the agent reads as unverified', async () => {
    h.projectRead.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    const res = await POST(req(check()))
    expect(res.status).toBe(500)
    expect(JSON.stringify(await res.json())).not.toContain('db down')
  })
})

describe('sharing not in force (DV-30): nothing is read, nothing refused', () => {
  test.each([
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on', { identity: true, permissions: true }, { enabled: true }],
    ["sharing switched on, Root's policy off", SHARING, {}],
  ] as Array<[string, Partial<RbacFlags>, Record<string, unknown>]>)('%s: allowed, another person\'s scan listed or not', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    h.policy = policy
    h.scans = [scan('partial_recon', 'alice')]
    h.authors = ['alice']
    expect(await ask(check())).toEqual([200, { allowed: true }])
    expect(h.orchestrator).not.toHaveBeenCalled()
    expect(h.agentAuthors).not.toHaveBeenCalled()
    expect(h.projectRead).not.toHaveBeenCalled()
  })

  test('contrast, sharing in force: the same state is refused (the cases above are not vacuous)', async () => {
    h.scans = [scan('partial_recon', 'alice')]
    expect((await ask(check()))[0]).toBe(409)
  })
})
