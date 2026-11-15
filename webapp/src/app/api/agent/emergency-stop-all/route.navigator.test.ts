/**
 * The emergency stop ends AI Navigator answers too (plan §5.7): a member's press aborts their own
 * registry runs only; the global scope aborts every one. Both are added to the audited count.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ session: null as unknown, principal: null as unknown, audits: [] as Array<Record<string, unknown>> }))
vi.mock('@/lib/session', () => ({ requireSession: async () => h.session }))
vi.mock('@/lib/authz/principal', () => ({ loadPrincipal: async () => h.principal }))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => { h.audits.push(e) } }))
vi.mock('@/lib/prisma', () => ({ default: { auditLog: { findFirst: async () => ({ createdAt: new Date('2026-06-01') }) } } }))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: async () => new Response(JSON.stringify({ stopped: 1 }), { status: 200, headers: { 'content-type': 'application/json' } }),
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests } from '@/lib/navigator/runRegistry'

function live(personId: string) {
  const r = navigatorRuns().reserve({ personId, projectId: `P-${personId}` })
  if (!r.ok) throw new Error()
  navigatorRuns().complete(r.runId, { threadId: `T-${personId}`, tenantId: personId, actorId: null,
    login: { userId: personId, sessionVersion: 0, deviceSessionId: null, actAsStartId: null } })
  return navigatorRuns().get(r.runId)!
}

beforeEach(() => {
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
  resetSharedToolsForTests()
  setFlagsForTests({})
  h.audits = []
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('emergency stop and AI Navigator', () => {
  test('a member stops only their own Navigator answers', async () => {
    h.session = { userId: 'member-1', role: 'standard' }
    h.principal = { id: 'member-1', email: 'm@x', role: 'standard', hasPassword: true, createdAt: new Date('2026-09-01'), legacyGrants: [] }
    const mine = live('member-1')
    const other = live('member-2')
    const res = await POST()
    expect(await res.json()).toEqual({ scope: 'own', stopped: 2 })
    expect(mine.abort.signal.aborted).toBe(true)
    expect(other.abort.signal.aborted).toBe(false)
  })

  test('an admin\'s global stop ends every Navigator answer', async () => {
    h.session = { userId: 'admin-1', role: 'admin' }
    h.principal = { id: 'admin-1', email: 'a@x', role: 'admin', hasPassword: true, createdAt: new Date('2026-09-01'), legacyGrants: [] }
    const a = live('member-1')
    const b = live('member-2')
    const res = await POST()
    expect(await res.json()).toEqual({ scope: 'all', stopped: 3 })
    expect([a.abort.signal.aborted, b.abort.signal.aborted]).toEqual([true, true])
    expect(h.audits.find((e) => e.action === 'agent.emergency_stop')).toMatchObject({ after: { scope: 'all', count: 3 } })
  })
})
