/**
 * The AI Navigator step of `onAccessReduced` (plan §5.7, §10.2 rows 12 and 29): every plan ends the
 * matching Navigator runs, the session plans included (sign out everywhere, a credentials reset, a
 * device revoke); a device revoke with its sid ends only that device's runs; a plan that ends the
 * account's impersonations also ends the runs it opened acting as someone; `navigator_disallowed`
 * closes no socket and stops nothing else.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({ agent: [] as Array<[string, unknown]> }))
vi.mock('@/lib/prisma', () => ({ default: {
  scanJob: { findMany: async () => [] }, jobQueue: { findMany: async () => [] }, scanSchedule: { findMany: async () => [] },
} }))
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async (b: unknown) => { h.agent.push(['/ws/close', b]); return { ok: true, closed: 0 } }) }))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: vi.fn(async (path: string) => { h.agent.push([path, null]); return new Response(JSON.stringify({ stopped: 0 }), { status: 200 }) }),
}))
vi.mock('./actAs', () => ({ endOpenImpersonationsQuietly: async () => {} }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: async () => null, LIVE_TRIAGE_STATUSES: [] }))
vi.mock('@/lib/triage/actions', () => ({ stopRun: async () => ({}) }))

import { onAccessReduced, PLANS, type AccessReducedReason } from './revocation'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests, type RunLogin } from '@/lib/navigator/runRegistry'

function live(personId: string, projectId: string, over: Partial<RunLogin> & { actorId?: string } = {}) {
  const r = navigatorRuns().reserve({ personId, projectId })
  if (!r.ok) throw new Error()
  navigatorRuns().complete(r.runId, {
    threadId: `T-${r.runId}`, tenantId: 'owner', actorId: over.actorId ?? null,
    login: { userId: over.actorId ?? personId, sessionVersion: 0, deviceSessionId: over.deviceSessionId ?? null, actAsStartId: null },
  })
  return navigatorRuns().get(r.runId)!
}

beforeEach(() => {
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
  h.agent = []
})

describe('the Navigator step', () => {
  test.each(Object.keys(PLANS).filter((r) => r !== 'navigator_disallowed') as AccessReducedReason[])('%s ends the person\'s runs', async (reason) => {
    const mine = live('bob', 'P1')
    const other = live('carol', 'P1')
    const out = await (reason.startsWith('share_') || reason === 'consent_withdrawn'
      ? onAccessReduced('P1', 'bob', reason as never)
      : onAccessReduced(null, 'bob', reason as never))
    expect(mine.abort.signal.aborted).toBe(true)
    expect(other.abort.signal.aborted).toBe(false)
    expect(out.navigator).toEqual({ stopped: 1 })
  })

  test('a project reason ends only that project\'s runs', async () => {
    const here = live('bob', 'P1')
    const elsewhere = live('bob', 'P2')
    await onAccessReduced('P1', 'bob', 'share_revoked')
    expect(here.abort.signal.aborted).toBe(true)
    expect(elsewhere.abort.signal.aborted).toBe(false)
  })

  test('a device revoke with its sid ends only that device\'s runs', async () => {
    const phone = live('bob', 'P1', { deviceSessionId: 'sid-phone' })
    const laptop = live('bob', 'P2', { deviceSessionId: 'sid-laptop' })
    await onAccessReduced(null, 'bob', 'device_session_revoked', { sid: 'sid-phone' })
    expect(phone.abort.signal.aborted).toBe(true)
    expect(laptop.abort.signal.aborted).toBe(false)
  })

  test('sign out everywhere also ends what the admin opened acting as someone', async () => {
    const acting = live('alice', 'P1', { actorId: 'admin' })
    await onAccessReduced(null, 'admin', 'sessions_revoked')
    expect(acting.abort.signal.aborted).toBe(true)
  })

  test('navigator_disallowed closes no socket and calls nothing but the Navigator stop', async () => {
    const run = live('bob', 'P1')
    const out = await onAccessReduced('P1', 'bob', 'navigator_disallowed')
    expect(run.abort.signal.aborted).toBe(true)
    expect(h.agent).toEqual([])
    expect(out.runs).toBeUndefined()
    expect(out.navigator).toEqual({ stopped: 1 })
  })
})
