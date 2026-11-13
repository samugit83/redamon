/**
 * The agent-run quota at the chat ticket (step 6.8, GV-11). With RBAC_GOVERNANCE_ENABLED on and a
 * maxConcurrentAgentRuns for the session's person (the ticket's `sub`, as the agent keys runs), the
 * route asks the agent how many of that person's runs are in progress (`GET /agent-sessions/count`,
 * step 6.5) and refuses at the cap with 409 `quota_exceeded`, before any owner spend is recorded;
 * a reconnect to a session whose run is in progress is never refused; when the agent cannot say
 * (unreachable, 503, a malformed answer) the ticket is refused 503 (fail closed) and logged. Other
 * sockets, an unlimited person and the switch off ask the agent nothing.
 *
 * The person's quota is the real lib/authz/quotas.ts over a doubled instance row, account and
 * capability resolution; the agent is a double of agentFetch.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  person: 'collab-1',
  audit: [] as Array<Record<string, unknown>>,
  createWsTicket: vi.fn(),
  agent: vi.fn(),
  quotas: {} as unknown,
  instanceRead: vi.fn(),
}))

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_r: unknown, permission: string, opts: { projectId?: string }) => ({
    session: { userId: h.person, role: 'standard' }, principal: { id: h.person, role: 'standard' }, actingAs: null,
    effective: { userId: h.person }, permission, capabilities: {},
    access: { project: { id: opts.projectId, userId: 'owner-1' }, level: h.person === 'owner-1' ? 'owner' : 'write', toggles: { rawData: true }, via: 'share' },
  }),
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: async () => ({ session: { userId: h.person, role: 'standard' }, principal: { id: h.person, role: 'standard' }, actingAs: null }),
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async (_s: unknown, projectId: string) => ({
    project: { id: projectId, userId: 'owner-1' }, level: 'write',
    toggles: { rawData: true, runScans: true, useAgent: true, exploit: true, manage: false }, via: 'share',
  }),
}))
vi.mock('@/lib/auditActor', async (orig) => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  signedInActor: async () => ({ id: h.person, email: `${h.person}@example.test` }),
}))
vi.mock('@/lib/authz/principal', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/principal')>()),
  loadPrincipal: async (id: string) => ({ id, role: 'standard', status: 'active', legacyGrants: [], permissionSets: [], permissionOverrides: [] }),
}))
vi.mock('@/lib/authz/capabilities', () => ({
  resolveCapabilities: async () => ({ accountType: 'member', sets: [{ id: 'builtin:default-member', name: 'Default member', kind: 'member', via: 'default' }] }),
}))
vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => { h.instanceRead(); return { quotas: h.quotas } },
}))
vi.mock('@/lib/agentFetch', () => ({ agentFetch: (...a: unknown[]) => h.agent(...a) }))
vi.mock('@/lib/authz/sharedTools', () => ({ sharedToolAccess: async () => ({ allowed: true, via: 'permission' }) }))
vi.mock('@/lib/authz/agentCap', () => ({ agentTicketCap: async () => [] }))
vi.mock('@/lib/authz/projectWriters', () => ({ secondWriterResponse: async () => null }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/auth', () => ({ createWsTicket: (...a: unknown[]) => h.createWsTicket(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { h.audit.push(data); return data } },
    // A ticket's session that no conversation holds yet (5.3 review: sessionTicketRefusal).
    conversation: { findUnique: async () => null },
  },
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'

const post = (socket = 'agent', sessionId = 's1') => POST(new NextRequest('http://x/api/agent/ws-ticket', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ projectId: 'P1', sessionId, socket }),
}))
const ok = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body })
const agentAnswers = (count: number | 'down' | number[] , sessions: unknown[] = []) => {
  h.agent.mockImplementation(async (path: string) => {
    if (count === 'down') throw new Error('unreachable')
    if (path.startsWith('/agent-sessions/count')) return Array.isArray(count) ? ok({ error: 'agent not ready' }, count[0]) : ok({ user_id: h.person, count })
    if (path === '/agent-sessions/all') return ok({ sessions })
    return ok({}, 404)
  })
}
const spends = () => h.audit.filter((r) => r.action === 'credits.used')

beforeEach(() => {
  h.person = 'collab-1'
  h.audit = []
  h.agent.mockReset()
  h.instanceRead.mockClear()
  h.createWsTicket.mockReset().mockResolvedValue('signed.ticket')
  h.quotas = { defaults: { maxConcurrentAgentRuns: 1 } }
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('agent run cap', () => {
  test('under the cap the ticket is minted; the agent is asked for the session\'s person', async () => {
    agentAnswers(0)
    const res = await post()
    expect(res.status).toBe(200)
    expect(h.agent.mock.calls[0][0]).toBe('/agent-sessions/count?user_id=collab-1')
    expect(h.createWsTicket).toHaveBeenCalledTimes(1)
  })

  test('at the cap: 409 quota_exceeded, no ticket and no spend recorded, logged', async () => {
    agentAnswers(1, [{ user_id: 'collab-1', project_id: 'P9', session_id: 'other', running: true }])
    const res = await post()
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'quota_exceeded', quota: 'maxConcurrentAgentRuns', limit: 1 })
    expect(h.createWsTicket).not.toHaveBeenCalled()
    expect(spends()).toEqual([])
    expect(console.warn).toHaveBeenCalledWith('[rbac] quota_exceeded quota=maxConcurrentAgentRuns user=collab-1 limit=1 used=1')
  })

  test('a reconnect to the session whose run is in progress is never refused', async () => {
    agentAnswers(1, [{ user_id: 'collab-1', project_id: 'P1', session_id: 's1', running: true }])
    expect((await post('agent', 's1')).status).toBe(200)
    expect((await post('agent', 's2')).status).toBe(409)
  })

  test('the agent cannot say (unreachable, 503, malformed): 503, no ticket, logged; never read as zero', async () => {
    for (const answer of ['down', [503]] as const) {
      agentAnswers(answer as never)
      const res = await post()
      expect(res.status).toBe(503)
      expect(await res.json()).toMatchObject({ code: 'agent_run_count_unavailable' })
    }
    h.agent.mockImplementation(async () => ok({ count: 'many' }))
    expect((await post()).status).toBe(503)
    expect(h.createWsTicket).not.toHaveBeenCalled()
    expect((console.warn as unknown as { mock: { calls: unknown[][] } }).mock.calls
      .some(([l]) => String(l).startsWith('[rbac] agent run quota unreadable user=collab-1'))).toBe(true)
  })

  test('other sockets, an unlimited person and the switch off ask the agent nothing', async () => {
    agentAnswers(9)
    expect((await post('cypherfix-codefix')).status).toBe(200)
    h.quotas = { defaults: { maxConcurrentAgentRuns: null } }
    expect((await post()).status).toBe(200)
    setFlagsForTests({ identity: true, permissions: true })
    h.quotas = { defaults: { maxConcurrentAgentRuns: 0 } }
    h.instanceRead.mockClear()
    expect((await post()).status).toBe(200)
    expect(h.instanceRead).not.toHaveBeenCalled()
    expect(h.agent).not.toHaveBeenCalled()
  })
})
