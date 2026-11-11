/**
 * POST /api/agent/emergency-stop-all — HD-07 (F-06).
 *
 * The emergency stop cancelled every user's agent runs on the shared instance for any
 * signed-in account. Now the global stop is one of the shared tools: an admin (or a
 * pre-upgrade account under the escape hatch) keeps it; anyone else stops only their
 * own runs through the agent's /agent-sessions/stop-for. The answer names the scope,
 * and each press writes `agent.emergency_stop` (scope, count). GET tells the toolbar
 * which scope a press would have, without counting as a use.
 *
 * The session and the account read are mocked; sharedToolAccess is the real one.
 *
 * Run: npx vitest run src/app/api/agent/emergency-stop-all/route.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const mockRequireSession = vi.fn()
const mockLoadPrincipal = vi.fn()
const mockWriteAudit = vi.fn()
const mockCutoff = vi.fn()
const mockAgentFetch = vi.fn()

vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => mockRequireSession(...a),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: (...a: unknown[]) => mockLoadPrincipal(...a),
}))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => mockWriteAudit(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: { auditLog: { findFirst: (...a: unknown[]) => mockCutoff(...a) } },
}))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
}))

import { GET, POST } from './route'
import { AgentUnreachableError } from '@/lib/agentFetch'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'

const CUTOFF = new Date('2026-06-01T00:00:00Z')
const BEFORE_CUTOFF = new Date('2026-01-01T00:00:00Z')
const AFTER_CUTOFF = new Date('2026-09-01T00:00:00Z')

function principal(id: string, role: string, legacyGrants: string[] = [], createdAt = AFTER_CUTOFF) {
  return { id, email: `${id}@x`, role, hasPassword: true, createdAt, legacyGrants }
}

function signedIn(p: ReturnType<typeof principal>) {
  mockRequireSession.mockResolvedValue({ userId: p.id, role: p.role })
  mockLoadPrincipal.mockImplementation(async (id: string) => (id === p.id ? p : null))
}

const agentAnswers = (body: unknown, status = 200) =>
  mockAgentFetch.mockResolvedValue(new Response(JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json' },
  }))

// The handlers take no request: a client cannot name whose runs to stop.
const post = () => POST()
const get = () => GET()

function agentCall() {
  expect(mockAgentFetch).toHaveBeenCalledTimes(1)
  const [path, init] = mockAgentFetch.mock.calls[0] as [string, RequestInit]
  return { path, method: init.method, body: init.body ? JSON.parse(String(init.body)) : undefined }
}

const stopRows = () => mockWriteAudit.mock.calls.map(c => c[0]).filter(e => e.action === 'agent.emergency_stop')
const compatRows = () => mockWriteAudit.mock.calls.map(c => c[0]).filter(e => e.action === 'rbac.compat_used')

let warn: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  mockRequireSession.mockReset()
  mockLoadPrincipal.mockReset()
  mockWriteAudit.mockReset().mockResolvedValue(undefined)
  mockCutoff.mockReset().mockResolvedValue({ createdAt: CUTOFF })
  mockAgentFetch.mockReset()
  resetSharedToolsForTests()
  setFlagsForTests({})
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  warn.mockRestore()
})

describe('POST /api/agent/emergency-stop-all', () => {
  test('member → stop-for: only their own runs', async () => {
    signedIn(principal('member-1', 'standard'))
    agentAnswers({ stopped: 2 })

    const res = await post()

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ scope: 'own', stopped: 2 })
    expect(agentCall()).toEqual({ path: '/agent-sessions/stop-for', method: 'POST', body: { user_id: 'member-1' } })
    expect(stopRows()).toEqual([{
      actorId: 'member-1', action: 'agent.emergency_stop', targetType: 'user', targetId: 'member-1',
      after: { scope: 'own', count: 2, via: null }, source: 'ui',
    }])
  })

  test('admin → all: today\'s global stop', async () => {
    signedIn(principal('admin-1', 'admin'))
    agentAnswers({ stopped: 5 })

    const res = await post()

    expect(await res.json()).toEqual({ scope: 'all', stopped: 5 })
    expect(agentCall()).toEqual({ path: '/emergency-stop-all', method: 'POST', body: undefined })
    expect(stopRows()).toEqual([{
      actorId: 'admin-1', action: 'agent.emergency_stop', targetType: 'instance', targetId: null,
      after: { scope: 'all', count: 5, via: 'admin' }, source: 'ui',
    }])
  })

  test('compat pre-upgrade member → all, and the use is recorded', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    signedIn(principal('old-member', 'standard', [], BEFORE_CUTOFF))
    agentAnswers({ stopped: 1 })

    const res = await post()

    expect(await res.json()).toEqual({ scope: 'all', stopped: 1 })
    expect(agentCall().path).toBe('/emergency-stop-all')
    expect(stopRows()[0].after).toEqual({ scope: 'all', count: 1, via: 'compat' })
    expect(compatRows()).toEqual([expect.objectContaining({ actorId: 'old-member', targetId: 'emergency_stop_all' })])
  })

  test('the escape hatch does not open it for an account created after the upgrade', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    signedIn(principal('new-member', 'standard', [], AFTER_CUTOFF))
    agentAnswers({ stopped: 0 })

    expect(await (await post()).json()).toEqual({ scope: 'own', stopped: 0 })
    expect(agentCall().path).toBe('/agent-sessions/stop-for')
    expect(compatRows()).toEqual([])
  })

  test('no legacy grant opens the global stop', async () => {
    signedIn(principal('holder', 'standard', ['kali_terminal', 'shell_sessions', 'tunnels'], BEFORE_CUTOFF))
    agentAnswers({ stopped: 0 })

    expect((await (await post()).json()).scope).toBe('own')
    expect(agentCall().body).toEqual({ user_id: 'holder' })
  })

  test('the signed-in account is judged, read from the database', async () => {
    // A token still saying "admin" for an account the database now holds as a member.
    mockRequireSession.mockResolvedValue({ userId: 'demoted', role: 'admin' })
    mockLoadPrincipal.mockResolvedValue(principal('demoted', 'standard'))
    agentAnswers({ stopped: 0 })

    expect((await (await post()).json()).scope).toBe('own')
    expect(mockLoadPrincipal).toHaveBeenCalledWith('demoted')
  })

  test('no session → 401, nothing stopped', async () => {
    mockRequireSession.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))

    expect((await post()).status).toBe(401)
    expect(mockAgentFetch).not.toHaveBeenCalled()
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test('the account gone since the session read → 401, nothing stopped', async () => {
    mockRequireSession.mockResolvedValue({ userId: 'gone', role: 'standard' })
    mockLoadPrincipal.mockResolvedValue(null)

    expect((await post()).status).toBe(401)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a failed account read is a coded 500, never a stop of the wrong scope', async () => {
    signedIn(principal('member-1', 'standard'))
    mockLoadPrincipal.mockRejectedValue(Object.assign(new Error('db down: secret detail'), { code: 'P1001' }))
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})

    const res = await post()

    error.mockRestore()
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.code).toBe('P1001')
    expect(JSON.stringify(body)).not.toContain('secret detail')
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an unreachable agent → 503 agent_unreachable, no audit row', async () => {
    signedIn(principal('member-1', 'standard'))
    mockAgentFetch.mockRejectedValue(new AgentUnreachableError(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })))

    const res = await post()

    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('agent_unreachable')
    expect(stopRows()).toEqual([])
  })

  test('an agent refusal is passed on, no audit row', async () => {
    signedIn(principal('member-1', 'standard'))
    agentAnswers({ detail: 'Unauthorized' }, 401)

    const res = await post()

    expect(res.ok).toBe(false)
    expect((await res.json()).upstreamStatus).toBe(401)
    expect(stopRows()).toEqual([])
  })
})

describe('GET /api/agent/emergency-stop-all (the toolbar\'s scope)', () => {
  test.each([
    ['a member', 'own', principal('m', 'standard')],
    ['an admin', 'all', principal('a', 'admin')],
    ['a legacy holder', 'own', principal('h', 'standard', ['kali_terminal', 'shell_sessions', 'tunnels'])],
  ] as const)('%s → %s', async (_who, scope, p) => {
    signedIn(p)

    const res = await get()

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ scope })
    expect(mockAgentFetch).not.toHaveBeenCalled()
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test('a compat pre-upgrade member is told "all", and asking is not a use', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    signedIn(principal('old-member', 'standard', [], BEFORE_CUTOFF))

    expect(await (await get()).json()).toEqual({ scope: 'all' })
    expect(mockWriteAudit).not.toHaveBeenCalled()
    expect(warn).not.toHaveBeenCalled()
  })

  test('no session → 401', async () => {
    mockRequireSession.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await get()).status).toBe(401)
  })
})
