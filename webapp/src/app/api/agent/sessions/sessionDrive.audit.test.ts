/**
 * A drive is audited before it is forwarded (group 1, E3; S16b review round 3).
 *
 * The session manager may run a command after the agent stopped waiting for it (it waits up to 30 s
 * for the console): the route then answers the agent's 504, and with the audit written only after a
 * successful answer the command ran with no audit row, and a retry ran it twice. Now every forwarded
 * interact, kill and job kill writes an `attempted` row in `auditedTransaction` BEFORE the agent call
 * (no row, no drive), and a second row with the outcome (`ran`, `busy`, `no_answer`, `failed`), both
 * carrying the same `driveId` and never the command text. A refused drive (404) writes neither.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const events: string[] = []
const mockRequireSession = vi.fn()
const mockEffectiveUser = vi.fn()
const mockLoadPrincipal = vi.fn()
const mockConversations = vi.fn()
const mockWriteAudit = vi.fn()
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
    auditLog: { findFirst: vi.fn(async () => null) },
    $transaction: async (fn: (tx: unknown) => unknown) => fn({ tx: true }),
  },
}))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
}))
vi.mock('@/lib/sandbox/gateway', () => ({ sandboxMode: async () => 'shared', sandboxProjectsFor: async () => [] }))

import { POST as interact } from './[id]/interact/route'
import { POST as killSession } from './[id]/kill/route'
import { POST as killJob } from '../jobs/[id]/kill/route'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { setFlagsForTests } from '@/lib/authz/flags'

const NOW = new Date('2026-09-01T00:00:00Z')
const principal = (id: string, role = 'standard') => ({ id, email: `${id}@x`, role, hasPassword: true, createdAt: NOW, legacyGrants: [] as string[] })

function signedIn(real: ReturnType<typeof principal>) {
  mockRequireSession.mockResolvedValue({ userId: real.id, role: real.role })
  mockLoadPrincipal.mockImplementation(async (id: string) => (id === real.id ? real : null))
  mockEffectiveUser.mockResolvedValue({ userId: real.id })
}

const LIST = {
  sessions: [{ id: 1, type: 'shell', info: '', connection: '', target_ip: '', chat_session_id: 'chat-a' }],
  jobs: [{ id: 0, name: 'Exploit: multi/handler', payload: 'p', port: 4444 }],
  non_msf_sessions: [],
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

let driveAnswer: () => Response | Promise<Response>
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const post = (body?: unknown) => new NextRequest('http://x/api', {
  method: 'POST',
  ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
})
const attempts = () => mockWriteAuditTx.mock.calls.map(c => c[1])
const outcomes = () => mockWriteAudit.mock.calls.map(c => c[0])

beforeEach(() => {
  events.length = 0
  mockRequireSession.mockReset()
  mockEffectiveUser.mockReset()
  mockLoadPrincipal.mockReset()
  mockConversations.mockReset().mockImplementation(async () => [
    { sessionId: 'chat-a', projectId: 'project-a', project: { userId: 'member-a' } },
  ])
  mockWriteAudit.mockReset().mockImplementation(async () => { events.push('outcome row') })
  mockWriteAuditTx.mockReset().mockImplementation(async () => { events.push('attempt row') })
  driveAnswer = () => json({ busy: false, output: 'uid=0(root)' })
  mockAgentFetch.mockReset().mockImplementation(async (path: string) => {
    if (path === '/sessions') return json(LIST)
    events.push(`agent ${path}`)
    return driveAnswer()
  })
  resetSharedToolsForTests()
  setFlagsForTests({})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('every forwarded drive is audited before it reaches the agent', () => {
  test('interact: the attempted row is written in a transaction, then the command is forwarded, then the outcome', async () => {
    signedIn(principal('member-a'))
    const res = await interact(post({ command: 'cat /etc/shadow' }), params('1'))
    expect(res.status).toBe(200)
    expect(events).toEqual(['attempt row', 'agent /sessions/1/interact', 'outcome row'])
    const [tx, attempt] = mockWriteAuditTx.mock.calls[0]
    expect(tx).toEqual({ tx: true })
    expect(attempt).toMatchObject({
      action: 'agent.session_interact', targetType: 'msf_session', targetId: 'shared:1', actorId: 'member-a', source: 'ui',
      after: { projectId: 'project-a', via: 'owner', sandbox: 'shared', outcome: 'attempted' },
    })
    expect(outcomes()[0]).toMatchObject({ action: 'agent.session_interact', targetId: 'shared:1', after: { outcome: 'ran' } })
    expect(typeof attempt.after.driveId).toBe('string')
    expect(outcomes()[0].after.driveId).toBe(attempt.after.driveId)
    expect(JSON.stringify([attempts(), outcomes()])).not.toContain('shadow')
  })

  test('the attempted row cannot be written: nothing is forwarded', async () => {
    signedIn(principal('member-a'))
    mockWriteAuditTx.mockRejectedValue(new Error('database down'))
    const res = await interact(post({ command: 'id' }), params('1'))
    expect(res.status).toBe(500)
    expect(events.filter(e => e.startsWith('agent '))).toEqual([])
    expect(outcomes()).toEqual([])
  })

  test('the agent gave up waiting (its 504): the outcome is no_answer, and the browser gets the failure', async () => {
    signedIn(principal('member-a'))
    driveAnswer = () => json({ error: 'Session interaction timeout' }, 504)
    const res = await interact(post({ command: 'id' }), params('1'))
    expect(res.status).toBe(502)
    expect((await res.json()).upstreamStatus).toBe(504)
    expect(attempts()).toHaveLength(1)
    expect(outcomes()[0].after).toMatchObject({ outcome: 'no_answer', status: 504, driveId: attempts()[0].after.driveId })
  })

  test('the agent could not be reached at all: no_answer; another agent failure: failed', async () => {
    signedIn(principal('member-a'))
    driveAnswer = () => { throw new TypeError('fetch failed') }
    await interact(post({ command: 'id' }), params('1'))
    expect(outcomes()[0].after).toMatchObject({ outcome: 'no_answer' })
    mockWriteAudit.mockClear()
    driveAnswer = () => json({ error: 'The session manager\'s answer was refused' }, 502)
    await interact(post({ command: 'id' }), params('1'))
    expect(outcomes()[0].after).toMatchObject({ outcome: 'failed', status: 502 })
  })

  test('a busy console: the attempt and a busy outcome', async () => {
    signedIn(principal('member-a'))
    driveAnswer = () => json({ busy: true, message: 'Agent is executing a command, try again shortly' })
    expect((await interact(post({ command: 'id' }), params('1'))).status).toBe(200)
    expect(attempts()).toHaveLength(1)
    expect(outcomes()[0].after).toMatchObject({ outcome: 'busy' })
  })

  test('a session kill and a job kill are audited the same way', async () => {
    signedIn(principal('member-a'))
    expect((await killSession(post(), params('1'))).status).toBe(200)
    expect(events).toEqual(['attempt row', 'agent /sessions/1/kill', 'outcome row'])
    expect(attempts()[0]).toMatchObject({ action: 'agent.session_kill', targetId: 'shared:1', after: { outcome: 'attempted' } })
    events.length = 0
    signedIn(principal('admin-a', 'admin'))
    expect((await killJob(post(), params('0'))).status).toBe(200)
    expect(events).toEqual(['attempt row', 'agent /jobs/0/kill', 'outcome row'])
    expect(attempts()[1]).toMatchObject({ action: 'agent.job_kill', targetType: 'msf_job', targetId: 'shared:0', after: { outcome: 'attempted' } })
    expect(outcomes()[1].after).toMatchObject({ outcome: 'ran' })
  })

  test('a refused drive (not in the caller\'s view) writes neither row', async () => {
    signedIn(principal('member-b'))
    expect((await interact(post({ command: 'id' }), params('1'))).status).toBe(404)
    expect((await killSession(post(), params('1'))).status).toBe(404)
    expect([attempts(), outcomes(), events]).toEqual([[], [], []])
  })
})
