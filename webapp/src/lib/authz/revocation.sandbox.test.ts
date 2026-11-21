/**
 * The Kali sandbox step of `onAccessReduced` (group 1, S14; OD-G1-g, OD-G1-m, TD-17): a person's
 * sandboxes follow every loss of access once the change has committed. A project reason reconciles
 * the person's instances with their fresh lists (both views: own and act-as); a disabled, deleted or
 * stripped account stops both views, and so does a credentials reset and the first sign-in after it (a
 * possibly compromised account's sandbox starts clean); a sign-out everywhere, a root transfer, a
 * device revoke, a lost terminal grant and the Navigator switch leave the sandbox alone. The lifecycle hooks (lib/sandbox/lifecycle.ts) are a
 * double: their own tests cover the gateway calls, the shared-mode no-op and the retries.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/revocation.sandbox.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  accessChanged: vi.fn(),
  accountEnded: vi.fn(),
  events: [] as string[],
}))
vi.mock('@/lib/prisma', () => ({ default: {
  jobQueue: { findMany: async () => [] }, scanSchedule: { findMany: async () => [] },
  triageRun: { findMany: async () => [] }, tradecraftIngestionJob: { updateMany: async () => ({ count: 0 }) },
} }))
vi.mock('@/lib/agentSockets', () => ({
  closeAgentSockets: vi.fn(async () => { h.events.push('close sockets'); return { ok: true, closed: 0 } }),
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: vi.fn(async (path: string) => { h.events.push(`agent ${path}`); return new Response(JSON.stringify({ stopped: 0 }), { status: 200 }) }),
}))
vi.mock('./actAs', () => ({ endOpenImpersonationsQuietly: async () => {} }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: async () => null, LIVE_TRIAGE_STATUSES: [] }))
vi.mock('@/lib/triage/actions', () => ({ stopRun: async () => ({}) }))
vi.mock('@/lib/tradecraft/deleteCleanup', () => ({ cancelUserTradecraftJobs: async () => ({ flagged: 0 }) }))
vi.mock('@/lib/sandbox/lifecycle', () => ({
  sandboxAccessChanged: (...a: unknown[]) => { h.events.push('sandbox'); return h.accessChanged(...a) },
  sandboxAccountEnded: (...a: unknown[]) => { h.events.push('sandbox'); return h.accountEnded(...a) },
}))

import { onAccessReduced, PLANS, type AccessReducedReason, type ProjectReduction } from './revocation'

const PROJECT_REASONS: ProjectReduction[] = ['share_revoked', 'share_left', 'share_expired', 'share_force_revoked', 'share_reduced', 'consent_withdrawn']
const ACCOUNT_STOPS = [
  ['account_disabled', 'account_disabled'], ['account_deleted', 'account_deleted'], ['capability_removed', 'access_lost'],
  ['credentials_reset', 'access_lost'], ['reset_link_used', 'access_lost'],
] as const
const NONE: AccessReducedReason[] = ['navigator_disallowed', 'sessions_revoked', 'root_transferred', 'device_session_revoked', 'terminal_grant_removed']

const reduce = (reason: AccessReducedReason) => (PROJECT_REASONS.includes(reason as ProjectReduction) || reason === 'navigator_disallowed'
  ? onAccessReduced('P1', 'bob', reason as ProjectReduction)
  : onAccessReduced(null, 'bob', reason as never))
const errorLines = () => vi.mocked(console.error).mock.calls.map((c) => String(c[0]))

beforeEach(() => {
  h.events = []
  h.accessChanged.mockReset().mockResolvedValue({ mode: 'per_user', stopped: 1 })
  h.accountEnded.mockReset().mockResolvedValue({ mode: 'per_user', stopped: 2 })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('which plan touches the sandbox', () => {
  test('every reason has a sandbox plan: reconcile for a lost project, stop for an ended account, none otherwise', () => {
    for (const reason of PROJECT_REASONS) expect([reason, PLANS[reason].sandbox]).toEqual([reason, 'reconcile'])
    for (const [reason] of ACCOUNT_STOPS) expect([reason, PLANS[reason].sandbox]).toEqual([reason, 'stop'])
    for (const reason of NONE) expect([reason, PLANS[reason].sandbox]).toEqual([reason, 'none'])
    expect(Object.keys(PLANS).sort()).toEqual([...PROJECT_REASONS, ...ACCOUNT_STOPS.map(([r]) => r), ...NONE].sort())
  })

  test.each(PROJECT_REASONS)('%s reconciles the person (both views), never the owner', async (reason) => {
    const out = await onAccessReduced('P1', 'bob', reason as never, { ownerId: 'alice' })
    expect(h.accessChanged).toHaveBeenCalledTimes(1)
    expect(h.accessChanged).toHaveBeenCalledWith(['bob'], undefined)
    expect(h.accountEnded).not.toHaveBeenCalled()
    expect(out.sandbox).toEqual({ stopped: 1 })
    expect(out.failed).toEqual([])
  })

  test.each(ACCOUNT_STOPS)('%s stops both views with the reason %s', async (reason, stopReason) => {
    const out = await onAccessReduced(null, 'bob', reason)
    expect(h.accountEnded).toHaveBeenCalledWith('bob', stopReason, undefined)
    expect(h.accessChanged).not.toHaveBeenCalled()
    expect(out.sandbox).toEqual({ stopped: 2 })
  })

  test.each(NONE)('%s leaves the sandbox alone', async (reason) => {
    const out = await reduce(reason)
    expect(h.accessChanged).not.toHaveBeenCalled()
    expect(h.accountEnded).not.toHaveBeenCalled()
    expect(out.sandbox).toBeUndefined()
  })
})

describe('the step', () => {
  test('runs after the agent has stopped the runs and closed the sockets (their work ends before its container)', async () => {
    await onAccessReduced('P1', 'bob', 'share_revoked')
    expect(h.events).toEqual(['agent /agent-sessions/stop-for', 'close sockets', 'sandbox'])
    h.events = []
    await onAccessReduced(null, 'bob', 'account_deleted')
    expect(h.events).toEqual(['agent /agent-sessions/stop-for', 'close sockets', 'sandbox'])
  })

  test('shared mode: no sandbox key, nothing failed', async () => {
    h.accessChanged.mockResolvedValue({ mode: 'shared' })
    h.accountEnded.mockResolvedValue({ mode: 'shared' })
    const project = await onAccessReduced('P1', 'bob', 'share_revoked')
    const account = await onAccessReduced(null, 'bob', 'account_disabled')
    for (const out of [project, account]) {
      expect(out.sandbox).toBeUndefined()
      expect(out.failed).toEqual([])
    }
  })

  test('a failure lands in failed, is logged, and the change stands', async () => {
    h.accessChanged.mockResolvedValue({ error: 'orchestrator_unreachable', stopped: 0 })
    const out = await onAccessReduced('P1', 'bob', 'share_expired')
    expect(out.sandbox).toEqual({ error: 'orchestrator_unreachable' })
    expect(out.failed).toEqual(['sandbox'])
    expect(errorLines()).toContain('[rbac] revocation step failed step=sandbox reason=share_expired user=bob project=P1: orchestrator_unreachable')
    h.accountEnded.mockResolvedValue({ error: 'sandbox_timeout', stopped: 0 })
    const ended = await onAccessReduced(null, 'bob', 'account_deleted')
    expect(ended.sandbox).toEqual({ error: 'sandbox_timeout' })
    expect(ended.failed).toEqual(['sandbox'])
  })

  test('a hook that throws (it should not) is a failure, never an exception', async () => {
    h.accountEnded.mockRejectedValue(Object.assign(new Error('boom'), { code: 'P1001' }))
    const out = await onAccessReduced(null, 'bob', 'account_disabled')
    expect(out.sandbox).toEqual({ error: 'P1001' })
    expect(out.failed).toEqual(['sandbox'])
  })

  test("the actor of the change reaches the hook when the caller names it (else the hook reads the request's)", async () => {
    const admin = { actorId: 'admin-1', onBehalfOfUserId: null, actorEmail: null }
    await onAccessReduced('P1', 'bob', 'share_force_revoked', { actor: admin })
    expect(h.accessChanged).toHaveBeenCalledWith(['bob'], admin)
    await onAccessReduced(null, 'bob', 'account_disabled', { actor: null })
    expect(h.accountEnded).toHaveBeenCalledWith('bob', 'account_disabled', null)
  })

  test('the summary line counts the sandboxes stopped', async () => {
    await onAccessReduced('P1', 'bob', 'share_revoked')
    const info = vi.mocked(console.info).mock.calls.map((c) => String(c[0]))
    expect(info.some((l) => l.startsWith('[rbac] revocation reason=share_revoked user=bob project=P1') && l.includes(' sandbox=1'))).toBe(true)
  })
})
