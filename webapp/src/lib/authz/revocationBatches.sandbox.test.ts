/**
 * The batch loops that call `onAccessReduced` (a capability removed from a set, `endSessionsOf`; the
 * expiry sweep's ended shares, `closeEndedShares`) stop asking the agent after a batch whose socket
 * closes all failed. The Kali sandbox step talks to the orchestrator, not the agent, so the people
 * after the break still get it (group 1, S14; both reviews of S14). The sweep also runs the sandbox
 * backstop (`reconcileRunningSandboxes`) every time, whatever the switches, and its outcome never
 * changes the sweep's answer.
 *
 * The real revocation path and sweep over doubles: Prisma (12 shares expired), the agent (every close
 * refused), the lifecycle hooks.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/revocationBatches.sandbox.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  accessChanged: vi.fn(),
  accountEnded: vi.fn(),
  accountsEnded: vi.fn(),
  backstop: vi.fn(),
  agentUp: false,
}))
vi.mock('@/lib/prisma', () => ({ default: {
  jobQueue: { findMany: async () => [] }, scanSchedule: { findMany: async () => [] },
  triageRun: { findMany: async () => [] }, tradecraftIngestionJob: { updateMany: async () => ({ count: 0 }) },
  projectCollaborator: {
    findMany: async () => Array.from({ length: 12 }, (_, i) => ({
      projectId: 'P1', userId: `u${i}`, access: 'write', rawData: false, runScans: false, useAgent: true,
      exploit: true, manage: false, expiresAt: new Date(0), grantedById: 'owner',
    })),
  },
  projectBreakGlass: { deleteMany: async () => ({ count: 0 }) },
} }))
vi.mock('@/lib/auditForward', () => ({
  auditedTransaction: async (_p: unknown, fn: (tx: unknown) => unknown) => fn({ projectCollaborator: { deleteMany: async () => ({ count: 1 }) } }),
}))
vi.mock('@/lib/audit', () => ({ writeAuditTx: async () => {} }))
vi.mock('@/lib/agentSockets', () => ({
  closeAgentSockets: vi.fn(async () => (h.agentUp ? { ok: true, closed: 1 } : { ok: false, reason: 'agent_http_500' })),
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: vi.fn(async () => new Response('{}', { status: h.agentUp ? 200 : 500 })),
}))
vi.mock('./actAs', () => ({ endOpenImpersonationsQuietly: async () => {} }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: async () => null, LIVE_TRIAGE_STATUSES: [] }))
vi.mock('@/lib/triage/actions', () => ({ stopRun: async () => ({}) }))
vi.mock('@/lib/tradecraft/deleteCleanup', () => ({ cancelUserTradecraftJobs: async () => ({ flagged: 0 }) }))
vi.mock('./sharingPolicy', async (orig) => ({ ...(await orig<typeof import('./sharingPolicy')>()), sharingInForce: async () => ({ enabled: true, maxLevel: 'write' }) }))
vi.mock('@/lib/navigator/retention', () => ({ sweepNavigatorRetention: async () => 0 }))
vi.mock('@/lib/sandbox/lifecycle', () => ({
  sandboxAccessChanged: (...a: unknown[]) => h.accessChanged(...a),
  sandboxAccountEnded: (...a: unknown[]) => h.accountEnded(...a),
  sandboxAccountsEnded: (...a: unknown[]) => h.accountsEnded(...a),
  reconcileRunningSandboxes: (...a: unknown[]) => h.backstop(...a),
}))

import { setFlagsForTests } from './flags'
import { endSessionsOf } from './permissionAdmin'
import { sweepExpired } from './expirySweep'

const TWELVE = Array.from({ length: 12 }, (_, i) => `u${i}`)
const errorLines = () => vi.mocked(console.error).mock.calls.map((c) => String(c[0]))
/** Every person a sandbox hook was asked about, in call order. */
const reached = (fn: ReturnType<typeof vi.fn>, at: number) => fn.mock.calls.flatMap((c) => (Array.isArray(c[at]) ? c[at] : [c[at]]) as string[])

beforeEach(() => {
  h.agentUp = false
  h.accessChanged.mockReset().mockResolvedValue({ stopped: 1 })
  h.accountEnded.mockReset().mockResolvedValue({ stopped: 1 })
  h.accountsEnded.mockReset().mockResolvedValue({ stopped: 1 })
  h.backstop.mockReset().mockResolvedValue({ stopped: 0 })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => { setFlagsForTests(null); vi.restoreAllMocks() })

describe('a refused batch of socket closes no longer skips the sandbox step for the people after it', () => {
  test('endSessionsOf: 12 accounts lose a capability, the agent refuses the closes: all 12 sandboxes stop', async () => {
    const out = await endSessionsOf(TWELVE)
    const viaRevocation = reached(h.accountEnded, 0)
    const after = reached(h.accountsEnded, 0)
    expect(viaRevocation).toEqual(TWELVE.slice(0, 8))
    expect(after).toEqual(TWELVE.slice(8))
    expect(h.accountsEnded.mock.calls.map((c) => c[1])).toEqual(['access_lost'])
    // What the loop already did is unchanged: the count, the line, no agent call for the rest.
    expect(out).toEqual({ closed: 0, failed: 12 })
    expect(errorLines()).toContain('[rbac] socket-close failed for 4 more account(s): the agent did not answer')
  })

  test('endSessionsOf with the agent up: no extra stop (each account got it through the revocation path)', async () => {
    h.agentUp = true
    await endSessionsOf(TWELVE)
    expect(reached(h.accountEnded, 0)).toEqual(TWELVE)
    expect(h.accountsEnded).not.toHaveBeenCalled()
  })

  test('the expiry sweep: 12 shares expire, the agent refuses the closes: all 12 are reconciled, as the system', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    const out = await sweepExpired()
    expect(reached(h.accessChanged, 0).sort()).toEqual([...TWELVE].sort())
    expect(h.accessChanged.mock.calls.at(-1)).toEqual([TWELVE.slice(8), null])
    expect(out.socketCloseFailed).toBe(12)
    expect(errorLines()).toContain('[rbac] socket-close failed for 4 more expired share(s): the agent did not answer')
  })
})

describe('the sandbox backstop runs at every sweep', () => {
  test.each([
    ['every switch off', {}],
    ['sharing on', { identity: true, permissions: true, sharing: true }],
  ])('%s: asked once, after the rest', async (_what, flags) => {
    setFlagsForTests(flags)
    await sweepExpired()
    expect(h.backstop).toHaveBeenCalledTimes(1)
  })

  test("never awaited: a backstop still running does not hold the sweep's answer (the reaper awaits the sweep)", async () => {
    setFlagsForTests({})
    h.backstop.mockImplementation(() => new Promise(() => {}))
    await expect(sweepExpired()).resolves.toMatchObject({ failed: [] })
  })

  test('its failure is its own (logged by the hook): the sweep answers as before', async () => {
    setFlagsForTests({})
    h.backstop.mockResolvedValue({ error: 'orchestrator_unreachable', stopped: 0 })
    const failing = await sweepExpired()
    h.backstop.mockRejectedValue(new Error('it should never throw'))
    const throwing = await sweepExpired()
    for (const out of [failing, throwing]) {
      expect(out.failed).toEqual([])
      expect(Object.keys(out).sort()).toEqual(['at', 'failed', 'removed', 'socketCloseFailed'])
    }
  })
})
