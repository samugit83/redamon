/**
 * A drive (interact, kill, job kill) whose sandbox did not answer the agent's list (G-34): the
 * Sessions panel keeps that sandbox's last rows as stale, so a 404 "Not found" would tell the person
 * the session is gone. When the named instance is in the viewer's own `unavailable` list (the names
 * the list route already sends that viewer), the drive answers 503 `sandbox_unavailable`; any other
 * instance stays the 404 it was, so nothing new is named about another person's sandbox.
 *
 * Mocked: the session, the account read, Prisma, the agent and the orchestrator's list; the access
 * rule is the real one.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/agent/sessions/sessionDrive.unavailable.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  session: vi.fn(),
  effective: vi.fn(),
  principal: vi.fn(),
  agentFetch: vi.fn(),
  writeAudit: vi.fn(),
  writeAuditTx: vi.fn(),
  running: [] as Array<{ user_id: string; view: string; instance: string; host: string; token: string; state: string }>,
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => h.session(...a),
  getEffectiveUser: (...a: unknown[]) => h.effective(...a),
}))
vi.mock('@/lib/authz/principal', () => ({ loadPrincipal: (...a: unknown[]) => h.principal(...a) }))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => h.writeAudit(...a),
  writeAuditTx: (...a: unknown[]) => h.writeAuditTx(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: { findMany: async () => [] },
    project: { findMany: async () => [] },
    $transaction: async (fn: (tx: unknown) => unknown) => fn({}),
    auditLog: { findFirst: vi.fn(async () => null) },
  },
}))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
}))
vi.mock('@/lib/sandbox/gateway', () => ({ sandboxProjectsFor: async () => [] }))
vi.mock('@/lib/sandbox/orchestratorClient', async (orig) => ({
  ...(await orig<typeof import('@/lib/sandbox/orchestratorClient')>()),
  orchestratorList: async () => ({ sandboxes: h.running }),
}))

import { POST as killSession } from './[id]/kill/route'
import { POST as interact } from './[id]/interact/route'
import { POST as killJob } from '../jobs/[id]/kill/route'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { resetUnavailableNamingForTests } from '@/lib/authz/agentSessionsAccess'
import { setFlagsForTests } from '@/lib/authz/flags'

const NOW = new Date('2026-09-01T00:00:00Z')
const member = (id: string) => ({ id, email: `${id}@x`, role: 'standard', hasPassword: true, createdAt: NOW, legacyGrants: [] })
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const post = (sandbox: string, body?: unknown) => new NextRequest(`http://x/api?sandbox=${sandbox}`, {
  method: 'POST',
  ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
})
const drives = () => h.agentFetch.mock.calls.map((c) => c[0] as string).filter((p) => p !== '/sessions')

/** The agent's merged list: member-a's sandbox `aaaaa1` and member-b's `bbbbb1` did not answer. */
function agentList(unavailable: string[]) {
  h.agentFetch.mockImplementation(async (path: string) => (path === '/sessions'
    ? json({ sessions: [], jobs: [], non_msf_sessions: [], unavailable })
    : json({ busy: false })))
}

beforeEach(() => {
  for (const fn of [h.session, h.effective, h.principal, h.agentFetch, h.writeAudit, h.writeAuditTx]) fn.mockReset()
  h.writeAudit.mockResolvedValue(undefined)
  h.writeAuditTx.mockResolvedValue(undefined)
  const a = member('member-a')
  h.session.mockResolvedValue({ userId: a.id, role: a.role })
  h.principal.mockImplementation(async (id: string) => (id === a.id ? a : null))
  h.effective.mockResolvedValue({ userId: a.id })
  h.running = [
    { user_id: 'member-a', view: 'own', instance: 'aaaaa1', host: 'h-a', token: 't-a', state: 'running' },
    { user_id: 'member-b', view: 'own', instance: 'bbbbb1', host: 'h-b', token: 't-b', state: 'running' },
  ]
  resetSharedToolsForTests()
  resetUnavailableNamingForTests()
  setFlagsForTests({})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('a drive into a sandbox that did not answer', () => {
  test('the viewer\'s own silent sandbox: 503 sandbox_unavailable for a kill, an interact and a job kill; nothing forwarded', async () => {
    agentList(['aaaaa1'])
    for (const res of [
      await killSession(post('aaaaa1'), params('1')),
      await interact(post('aaaaa1', { command: 'id' }), params('1')),
      await killJob(post('aaaaa1'), params('0')),
    ]) {
      expect(res.status).toBe(503)
      expect(await res.json()).toMatchObject({ code: 'sandbox_unavailable' })
    }
    expect(drives()).toEqual([])
    expect(h.writeAuditTx).not.toHaveBeenCalled()
  })

  test('another person\'s silent sandbox is not named to this viewer: still 404', async () => {
    agentList(['bbbbb1'])
    expect((await killSession(post('bbbbb1'), params('2'))).status).toBe(404)
    expect(drives()).toEqual([])
  })

  test('a sandbox that answered but holds no such session: still 404', async () => {
    agentList([])
    expect((await killSession(post('aaaaa1'), params('9'))).status).toBe(404)
  })
})
