/**
 * The sandbox lifecycle hooks (group 1, S14; B.7, B.10, TD-17, TD-27): what access loss, an account's
 * end, a project's deletion and the emergency stop do to the per-user Kali sandboxes, through the
 * gateway (lib/sandbox/gateway.ts, a double here) and the orchestrator's reconcile (a double).
 *
 * Every test names the mode the gateway answers (the switch), never the contract's default.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sandbox/lifecycle.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  mode: 'per_user' as 'shared' | 'per_user',
  modeError: null as unknown,
  sandboxMode: vi.fn(),
  lists: {} as Record<string, { own: string[]; actAs: string[] }>,
  projectsFor: vi.fn(),
  reconcile: vi.fn(),
  stopSandbox: vi.fn(),
  stopAll: vi.fn(),
  stopProject: vi.fn(),
  touch: vi.fn(),
  assertUser: vi.fn(),
  list: vi.fn(),
  principal: vi.fn(),
  audit: [] as Array<Record<string, unknown>>,
  requestActor: vi.fn(),
}))

// vitest.setup.ts gives every other test a shared-mode double of this module.
vi.unmock('./lifecycle')
vi.mock('./gateway', () => ({
  sandboxMode: (...a: unknown[]) => h.sandboxMode(...a),
  sandboxProjectsFor: (...a: unknown[]) => h.projectsFor(...a),
  stopSandbox: (...a: unknown[]) => h.stopSandbox(...a),
  stopAllSandboxes: (...a: unknown[]) => h.stopAll(...a),
  stopProjectSandboxes: (...a: unknown[]) => h.stopProject(...a),
  touchSandbox: (...a: unknown[]) => h.touch(...a),
  assertSandboxUser: (...a: unknown[]) => h.assertUser(...a),
  listSandboxes: (...a: unknown[]) => h.list(...a),
}))
vi.mock('@/lib/authz/principal', () => ({ loadPrincipal: (...a: unknown[]) => h.principal(...a) }))
vi.mock('./orchestratorClient', async (orig) => ({
  ...(await orig<typeof import('./orchestratorClient')>()),
  orchestratorReconcile: (...a: unknown[]) => h.reconcile(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => { h.audit.push(e) } }))
vi.mock('@/lib/auditActor', () => ({ auditActor: (...a: unknown[]) => h.requestActor(...a) }))

import { OrchestratorUnreachable, SandboxError } from './orchestratorClient'
import {
  pendingSandboxStopsForTests, resetSandboxLifecycleForTests, retryPendingSandboxStops, sandboxAccessChanged, sandboxRetryIdleForTests,
  sandboxAccountEnded, sandboxAccountsEnded, sandboxEmergencyStop, sandboxProjectDeleted, warmUpSandbox, reconcileRunningSandboxes,
  BACKSTOP_MAX_PEOPLE, LIFECYCLE_DEADLINE_MS, WARM_UP_COOLDOWN_MS,
} from './lifecycle'

const ADMIN = { actorId: 'admin-1', onBehalfOfUserId: null, actorEmail: 'admin-1@example.test' }
const OWNER = { actorId: 'alice', onBehalfOfUserId: null, actorEmail: null }
const SYSTEM_ACTOR = { actorId: null, onBehalfOfUserId: null, actorEmail: null }
const unreachable = () => new OrchestratorUnreachable(Object.assign(new Error('connect'), { code: 'ECONNREFUSED' }))
const warnLines = () => vi.mocked(console.warn).mock.calls.map((c) => String(c[0]))

beforeEach(() => {
  resetSandboxLifecycleForTests()
  h.mode = 'per_user'
  h.modeError = null
  h.sandboxMode.mockReset().mockImplementation(async () => {
    if (h.modeError) throw h.modeError
    return h.mode
  })
  h.lists = { bob: { own: ['P-bob', 'P1'], actAs: ['P-bob'] }, carol: { own: ['P-carol'], actAs: ['P-carol'] }, dan: { own: [], actAs: [] } }
  h.projectsFor.mockReset().mockImplementation(async (userId: string, opts?: { actingAs?: boolean }) =>
    (opts?.actingAs ? h.lists[userId]?.actAs : h.lists[userId]?.own) ?? [])
  h.reconcile.mockReset().mockResolvedValue(0)
  h.stopSandbox.mockReset().mockResolvedValue(0)
  h.stopAll.mockReset().mockResolvedValue(0)
  h.stopProject.mockReset().mockResolvedValue({ ok: true, stopped: 0 })
  h.touch.mockReset().mockResolvedValue(undefined)
  h.assertUser.mockReset().mockResolvedValue(undefined)
  h.list.mockReset().mockResolvedValue({ mode: 'per_user', sandboxes: [] })
  h.principal.mockReset().mockImplementation(async (id: string) => ({ id, status: 'active' }))
  h.audit = []
  h.requestActor.mockReset().mockResolvedValue(OWNER)
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  resetSandboxLifecycleForTests()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('shared mode: nothing is asked', () => {
  test('every hook answers shared and calls nothing else', async () => {
    h.mode = 'shared'
    expect(await sandboxAccessChanged(['bob'], ADMIN)).toEqual({ mode: 'shared' })
    expect(await sandboxAccountEnded('bob', 'account_deleted', ADMIN)).toEqual({ mode: 'shared' })
    expect(await sandboxProjectDeleted('P1', ADMIN)).toEqual({ mode: 'shared' })
    expect(await sandboxEmergencyStop({ scope: 'all' }, ADMIN)).toEqual({ mode: 'shared' })
    expect(await sandboxEmergencyStop({ scope: 'own', userId: 'bob' }, ADMIN)).toEqual({ mode: 'shared' })
    for (const fn of [h.projectsFor, h.reconcile, h.stopSandbox, h.stopAll, h.stopProject, h.requestActor]) {
      expect(fn).not.toHaveBeenCalled()
    }
    expect(h.audit).toEqual([])
    expect(pendingSandboxStopsForTests()).toEqual([])
  })

  test('the mode is asked once for a burst of hooks (the probe is shared while in flight)', async () => {
    h.mode = 'shared'
    await Promise.all([sandboxAccessChanged(['bob']), sandboxAccessChanged(['carol']), sandboxAccountEnded('dan', 'account_disabled')])
    expect(h.sandboxMode).toHaveBeenCalledTimes(1)
  })
})

describe('access changed (a share lost, consent withdrawn, a project deleted)', () => {
  test('each person is reconciled with both fresh lists; nothing is started', async () => {
    const out = await sandboxAccessChanged(['bob', 'carol', 'bob'], ADMIN)
    expect(out).toEqual({ mode: 'per_user', stopped: 0 })
    expect(h.reconcile.mock.calls).toEqual([['bob', ['P-bob', 'P1'], ['P-bob']], ['carol', ['P-carol'], ['P-carol']]])
    expect(h.stopSandbox).not.toHaveBeenCalled()
    expect(h.audit).toEqual([])
  })

  test('an instance stopped by the reconcile writes sandbox.stopped with the actor of the change', async () => {
    h.reconcile.mockResolvedValueOnce(2)
    expect(await sandboxAccessChanged(['bob'], ADMIN)).toEqual({ mode: 'per_user', stopped: 2 })
    expect(h.audit).toEqual([{
      ...ADMIN, action: 'sandbox.stopped', targetType: 'user', targetId: 'bob', after: { reason: 'access_lost', stopped: 2 }, source: 'system',
    }])
  })

  test('a person left with no allowed project is stopped with last_project_deleted', async () => {
    h.stopSandbox.mockResolvedValueOnce(1)
    expect(await sandboxAccessChanged(['dan'], OWNER)).toEqual({ mode: 'per_user', stopped: 1 })
    expect(h.reconcile).toHaveBeenCalledWith('dan', [], [])
    expect(h.stopSandbox).toHaveBeenCalledWith('dan', 'last_project_deleted', OWNER)
  })

  test('no actor given: the person signed in to this request; no request: the system', async () => {
    h.reconcile.mockResolvedValue(1)
    await sandboxAccessChanged(['bob'])
    expect(h.audit[0]).toMatchObject(OWNER)
    h.requestActor.mockRejectedValueOnce(new Error('cookies() was called outside a request scope'))
    await sandboxAccessChanged(['carol'])
    expect(h.audit[1]).toMatchObject(SYSTEM_ACTOR)
    h.mode = 'shared'
    h.requestActor.mockClear()
    await sandboxAccessChanged(['bob'])
    expect(h.requestActor).not.toHaveBeenCalled()
  })

  test('the system actor given as null stays null (the expiry sweep)', async () => {
    h.reconcile.mockResolvedValue(1)
    await sandboxAccessChanged(['bob'], null)
    expect(h.audit[0]).toMatchObject(SYSTEM_ACTOR)
    expect(h.requestActor).not.toHaveBeenCalled()
  })

  test('a failure is returned, never thrown; the other persons still go on', async () => {
    h.reconcile.mockImplementation(async (userId: string) => {
      if (userId === 'bob') throw unreachable()
      return 1
    })
    const out = await sandboxAccessChanged(['bob', 'carol'], ADMIN)
    expect(out).toEqual({ error: 'orchestrator_unreachable', stopped: 1 })
    expect(h.reconcile).toHaveBeenCalledTimes(2)
    expect(warnLines().some((l) => l.startsWith('[sandbox] access-loss stop not done') && l.includes('orchestrator_unreachable'))).toBe(true)
  })

  test('a list that cannot be read is a failure too (never a reconcile with a guessed list)', async () => {
    h.projectsFor.mockRejectedValueOnce(Object.assign(new Error('db'), { code: 'P1001' }))
    expect(await sandboxAccessChanged(['bob'], ADMIN)).toEqual({ error: 'P1001', stopped: 0 })
    expect(h.reconcile).not.toHaveBeenCalled()
  })

  test('an id the contract refuses is skipped, never sent', async () => {
    expect(await sandboxAccessChanged(['../etc', 'ensure', 'bob'], ADMIN)).toEqual({ mode: 'per_user', stopped: 0 })
    expect(h.reconcile.mock.calls.map((c) => c[0])).toEqual(['bob'])
  })

  test('no answer about the mode is a failure (never read as shared)', async () => {
    h.modeError = unreachable()
    expect(await sandboxAccessChanged(['bob'], ADMIN)).toEqual({ error: 'orchestrator_unreachable', stopped: 0 })
    expect(h.reconcile).not.toHaveBeenCalled()
    expect(pendingSandboxStopsForTests()).toEqual([{ key: 'user:bob', kind: 'reconcile' }])
  })
})

describe("an account's end", () => {
  test.each(['account_disabled', 'account_deleted', 'access_lost'] as const)('%s stops both views with that reason and the actor', async (reason) => {
    h.stopSandbox.mockResolvedValueOnce(2)
    expect(await sandboxAccountEnded('bob', reason, ADMIN)).toEqual({ mode: 'per_user', stopped: 2 })
    expect(h.stopSandbox).toHaveBeenCalledWith('bob', reason, ADMIN)
  })

  test('a deletion is sent to the orchestrator even when nothing runs (the output folders go)', async () => {
    h.stopSandbox.mockResolvedValueOnce(0)
    expect(await sandboxAccountEnded('bob', 'account_deleted', ADMIN)).toEqual({ mode: 'per_user', stopped: 0 })
    expect(h.stopSandbox).toHaveBeenCalledTimes(1)
    expect(h.stopSandbox).toHaveBeenCalledWith('bob', 'account_deleted', ADMIN)
  })

  test('a stop that fails is returned, never thrown, and kept for a retry', async () => {
    h.stopSandbox.mockRejectedValueOnce(new SandboxError(502, 'orchestrator_error'))
    expect(await sandboxAccountEnded('bob', 'account_deleted', ADMIN)).toEqual({ error: 'orchestrator_error', stopped: 0 })
    expect(pendingSandboxStopsForTests()).toEqual([{ key: 'user:bob', kind: 'stop', reason: 'account_deleted' }])
  })
})

describe('a project deleted (TD-27)', () => {
  test('every instance mounting it is stopped, with its actor', async () => {
    h.stopProject.mockResolvedValueOnce({ ok: true, stopped: 3 })
    expect(await sandboxProjectDeleted('P1', ADMIN)).toEqual({ mode: 'per_user', stopped: 3 })
    expect(h.stopProject).toHaveBeenCalledWith('P1', 'project_deleted', ADMIN)
  })

  test('a project id the contract refuses was never mounted: nothing to stop, nothing asked', async () => {
    expect(await sandboxProjectDeleted('../P1', ADMIN)).toEqual({ mode: 'per_user', stopped: 0 })
    expect(h.sandboxMode).not.toHaveBeenCalled()
    expect(h.stopProject).not.toHaveBeenCalled()
    expect(pendingSandboxStopsForTests()).toEqual([])
  })

  test("the gateway's failed outcome is returned and kept for a retry", async () => {
    h.stopProject.mockResolvedValueOnce({ ok: false, code: 'orchestrator_unreachable' })
    expect(await sandboxProjectDeleted('P1', ADMIN)).toEqual({ error: 'orchestrator_unreachable', stopped: 0 })
    expect(pendingSandboxStopsForTests()).toEqual([{ key: 'project:P1', kind: 'project' }])
  })
})

describe('the emergency stop', () => {
  test('instance-wide: every sandbox, with the presser', async () => {
    h.stopAll.mockResolvedValueOnce(4)
    expect(await sandboxEmergencyStop({ scope: 'all' }, ADMIN)).toEqual({ mode: 'per_user', stopped: 4 })
    expect(h.stopAll).toHaveBeenCalledWith('emergency', ADMIN)
  })

  test("a person's own: both their views, with the presser", async () => {
    h.stopSandbox.mockResolvedValueOnce(1)
    expect(await sandboxEmergencyStop({ scope: 'own', userId: 'bob' }, OWNER)).toEqual({ mode: 'per_user', stopped: 1 })
    expect(h.stopSandbox).toHaveBeenCalledWith('bob', 'emergency', OWNER)
  })

  test('stop-all throwing is returned, and an emergency is never retried later', async () => {
    h.stopAll.mockRejectedValueOnce(unreachable())
    expect(await sandboxEmergencyStop({ scope: 'all' }, ADMIN)).toEqual({ error: 'orchestrator_unreachable', stopped: 0 })
    h.stopSandbox.mockRejectedValueOnce(unreachable())
    expect(await sandboxEmergencyStop({ scope: 'own', userId: 'bob' }, ADMIN)).toEqual({ error: 'orchestrator_unreachable', stopped: 0 })
    expect(pendingSandboxStopsForTests()).toEqual([])
  })
})

describe('the deadline', () => {
  test('a hung orchestrator does not hold the change: the hook answers sandbox_timeout and keeps a retry', async () => {
    vi.useFakeTimers()
    h.reconcile.mockImplementation(() => new Promise(() => {}))
    const pending = sandboxAccessChanged(['bob'], ADMIN)
    await vi.advanceTimersByTimeAsync(LIFECYCLE_DEADLINE_MS + 1)
    expect(await pending).toEqual({ error: 'sandbox_timeout', stopped: 0 })
    expect(pendingSandboxStopsForTests()).toEqual([{ key: 'user:bob', kind: 'reconcile' }])
  })
})

describe('retries of a stop that failed (TD-17: access lost while the orchestrator was down)', () => {
  test('a failed reconcile is retried in the background and forgotten once it is done', async () => {
    vi.useFakeTimers()
    h.reconcile.mockRejectedValueOnce(unreachable())
    await sandboxAccessChanged(['bob'], ADMIN)
    expect(pendingSandboxStopsForTests()).toHaveLength(1)
    h.reconcile.mockResolvedValueOnce(1)
    await vi.advanceTimersByTimeAsync(60_000)
    await sandboxRetryIdleForTests()
    expect(h.reconcile).toHaveBeenCalledTimes(2)
    expect(h.reconcile).toHaveBeenLastCalledWith('bob', ['P-bob', 'P1'], ['P-bob'])
    expect(pendingSandboxStopsForTests()).toEqual([])
    expect(h.audit.at(-1)).toMatchObject({ ...ADMIN, after: { reason: 'access_lost', stopped: 1 } })
  })

  test('the next hook that reaches the orchestrator retries at once', async () => {
    vi.useFakeTimers()
    h.reconcile.mockRejectedValueOnce(unreachable())
    await sandboxAccessChanged(['bob'], ADMIN)
    await sandboxAccessChanged(['carol'], ADMIN)
    await vi.advanceTimersByTimeAsync(0)
    await sandboxRetryIdleForTests()
    expect(h.reconcile.mock.calls.map((c) => c[0])).toEqual(['bob', 'carol', 'bob'])
    expect(pendingSandboxStopsForTests()).toEqual([])
  })

  test('a deletion stays a deletion: a later reconcile of the same person does not replace it', async () => {
    h.stopSandbox.mockRejectedValueOnce(unreachable())
    await sandboxAccountEnded('bob', 'account_deleted', ADMIN)
    h.reconcile.mockRejectedValueOnce(unreachable())
    await sandboxAccessChanged(['bob'], ADMIN)
    expect(pendingSandboxStopsForTests()).toEqual([{ key: 'user:bob', kind: 'stop', reason: 'account_deleted' }])
    await retryPendingSandboxStops()
    expect(h.stopSandbox).toHaveBeenLastCalledWith('bob', 'account_deleted', ADMIN)
    expect(h.assertUser).not.toHaveBeenCalled()
    expect(pendingSandboxStopsForTests()).toEqual([])
  })

  test('a disable retried after the account came back reconciles instead of stopping', async () => {
    h.stopSandbox.mockRejectedValueOnce(unreachable())
    await sandboxAccountEnded('bob', 'account_disabled', ADMIN)
    h.assertUser.mockResolvedValueOnce(undefined)
    await retryPendingSandboxStops()
    expect(h.stopSandbox).toHaveBeenCalledTimes(1)
    expect(h.reconcile).toHaveBeenCalledWith('bob', ['P-bob', 'P1'], ['P-bob'])
  })

  test('a disable retried while the account is still refused stops', async () => {
    h.stopSandbox.mockRejectedValueOnce(unreachable())
    await sandboxAccountEnded('bob', 'account_disabled', ADMIN)
    h.assertUser.mockRejectedValueOnce(new SandboxError(403, 'sandbox_user_refused'))
    await retryPendingSandboxStops()
    expect(h.stopSandbox).toHaveBeenLastCalledWith('bob', 'account_disabled', ADMIN)
    expect(pendingSandboxStopsForTests()).toEqual([])
  })

  test('a project stop is retried; switched to shared meanwhile, the retry is dropped', async () => {
    h.stopProject.mockResolvedValueOnce({ ok: false, code: 'orchestrator_unreachable' })
    await sandboxProjectDeleted('P1', ADMIN)
    await retryPendingSandboxStops()
    expect(h.stopProject).toHaveBeenCalledTimes(2)
    expect(pendingSandboxStopsForTests()).toEqual([])
    h.stopProject.mockResolvedValueOnce({ ok: false, code: 'orchestrator_unreachable' })
    await sandboxProjectDeleted('P2', ADMIN)
    h.mode = 'shared'
    await retryPendingSandboxStops()
    expect(h.stopProject).toHaveBeenCalledTimes(3)
    expect(pendingSandboxStopsForTests()).toEqual([])
  })

  test("a mode read that failed still names the change's actor on the retry's row", async () => {
    h.modeError = unreachable()
    await sandboxAccessChanged(['bob'])
    h.stopSandbox.mockRejectedValueOnce(unreachable())
    await sandboxAccountEnded('carol', 'account_disabled')
    h.modeError = null
    h.reconcile.mockResolvedValue(1)
    h.assertUser.mockRejectedValueOnce(new SandboxError(403, 'sandbox_user_refused'))
    await retryPendingSandboxStops()
    expect(h.audit.find((r) => r.targetId === 'bob')).toMatchObject(OWNER)
    expect(h.stopSandbox).toHaveBeenLastCalledWith('carol', 'account_disabled', OWNER)
  })

  test('a refusal the orchestrator will always give (400) is not retried', async () => {
    h.stopProject.mockResolvedValueOnce({ ok: false, code: 'invalid_project_id' })
    await sandboxProjectDeleted('P1', ADMIN)
    expect(pendingSandboxStopsForTests()).toEqual([])
  })
})

describe('the warm-up (ws-ticket mint), coalesced per person and view', () => {
  test('a burst of mints warms each person and view up once', async () => {
    let finish: () => void = () => {}
    h.touch.mockImplementation(() => new Promise<void>((r) => { finish = r }))
    const actor = { actorId: 'bob', onBehalfOfUserId: null, actorEmail: null }
    for (let i = 0; i < 5; i++) void warmUpSandbox('bob', { actingAs: false, actor })
    void warmUpSandbox('bob', { actingAs: true, actor: ADMIN })
    void warmUpSandbox('carol', { actingAs: false, actor: null })
    expect(h.touch.mock.calls).toEqual([
      ['bob', { actingAs: false, actor }], ['bob', { actingAs: true, actor: ADMIN }], ['carol', { actingAs: false, actor: null }],
    ])
    finish()
  })

  test('after a warm-up, the same person and view wait out the cool-down', async () => {
    vi.useFakeTimers()
    await warmUpSandbox('bob', { actingAs: false, actor: null })
    await warmUpSandbox('bob', { actingAs: false, actor: null })
    expect(h.touch).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(WARM_UP_COOLDOWN_MS + 1)
    await warmUpSandbox('bob', { actingAs: false, actor: null })
    expect(h.touch).toHaveBeenCalledTimes(2)
  })

  test('a warm-up that throws is swallowed and still cools down', async () => {
    h.touch.mockRejectedValueOnce(new Error('boom'))
    await expect(warmUpSandbox('bob', { actingAs: false, actor: null })).resolves.toBeUndefined()
    await warmUpSandbox('bob', { actingAs: false, actor: null })
    expect(h.touch).toHaveBeenCalledTimes(1)
  })

  test('a warm-up never asks the mode itself (the gateway stays quiet until per-user is named)', async () => {
    await warmUpSandbox('bob', { actingAs: false, actor: null })
    expect(h.sandboxMode).not.toHaveBeenCalled()
  })
})

describe('several accounts ended at once (a capability removed from a set)', () => {
  test('each account is stopped with the reason, one deadline for all', async () => {
    h.stopSandbox.mockResolvedValue(1)
    expect(await sandboxAccountsEnded(['bob', 'carol', 'bob', '../x'], 'access_lost', ADMIN)).toEqual({ mode: 'per_user', stopped: 2 })
    expect(h.stopSandbox.mock.calls).toEqual([['bob', 'access_lost', ADMIN], ['carol', 'access_lost', ADMIN]])
    expect(h.sandboxMode).toHaveBeenCalledTimes(1)
  })

  test('one failing goes on with the next and is kept; past the deadline nobody more is visited', async () => {
    h.stopSandbox.mockImplementation(async (id: string) => { if (id === 'bob') throw unreachable(); return 1 })
    expect(await sandboxAccountsEnded(['bob', 'carol'], 'access_lost', ADMIN)).toEqual({ error: 'orchestrator_unreachable', stopped: 1 })
    expect(pendingSandboxStopsForTests()).toEqual([{ key: 'user:bob', kind: 'stop', reason: 'access_lost' }])
    resetSandboxLifecycleForTests()
    vi.useFakeTimers()
    h.stopSandbox.mockReset().mockImplementation(() => new Promise(() => {}))
    const pending = sandboxAccountsEnded(['bob', 'carol', 'dan'], 'access_lost', ADMIN)
    await vi.advanceTimersByTimeAsync(LIFECYCLE_DEADLINE_MS + 1)
    expect(await pending).toEqual({ error: 'sandbox_timeout', stopped: 0 })
    expect(h.stopSandbox).toHaveBeenCalledTimes(1)
    expect(pendingSandboxStopsForTests().map((p) => p.key).sort()).toEqual(['user:bob', 'user:carol', 'user:dan'])
  })
})

describe('the deadline stops the visit', () => {
  test('a reconcile past the deadline visits nobody more (the kept retries do the rest)', async () => {
    vi.useFakeTimers()
    let release: () => void = () => {}
    h.reconcile.mockImplementationOnce(() => new Promise((r) => { release = () => r(0) }))
    const pending = sandboxAccessChanged(['bob', 'carol'], ADMIN)
    await vi.advanceTimersByTimeAsync(LIFECYCLE_DEADLINE_MS + 1)
    expect(await pending).toEqual({ error: 'sandbox_timeout', stopped: 0 })
    release()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.reconcile).toHaveBeenCalledTimes(1)
  })
})

describe('a refused keep is not lost when the held retry succeeds on a stale list (second review F3)', () => {
  test('disable fails; re-enabled; the retry reads the old list; a revocation then fails and is refused; the retry reconciles again', async () => {
    // 1. The disable's stop fails: kept as a stop.
    h.stopSandbox.mockRejectedValueOnce(unreachable())
    await sandboxAccountEnded('bob', 'account_disabled', ADMIN)
    expect(pendingSandboxStopsForTests()).toEqual([{ key: 'user:bob', kind: 'stop', reason: 'account_disabled' }])
    // 2. Re-enabled: the retry reconciles instead, and has read bob's lists (P1 still in) when its call hangs.
    let finishRetry: (n: number) => void = () => {}
    h.reconcile.mockImplementationOnce(() => new Promise<number>((r) => { finishRetry = r }))
    const retry = retryPendingSandboxStops()
    await vi.waitFor(() => expect(h.reconcile).toHaveBeenCalledTimes(1))
    expect(h.reconcile.mock.calls[0]).toEqual(['bob', ['P-bob', 'P1'], ['P-bob']])
    // 3. Bob's share of P1 is revoked; its reconcile fails, and the keep is refused (a stop is held).
    h.lists.bob = { own: ['P-bob'], actAs: ['P-bob'] }
    h.reconcile.mockRejectedValueOnce(unreachable())
    expect(await sandboxAccessChanged(['bob'], OWNER)).toEqual({ error: 'orchestrator_unreachable', stopped: 0 })
    // 4. The retry's stale reconcile succeeds: it reconciles again on the fresh list before forgetting bob.
    finishRetry(0)
    await retry
    expect(h.reconcile).toHaveBeenCalledTimes(3)
    expect(h.reconcile.mock.calls[2]).toEqual(['bob', ['P-bob'], ['P-bob']])
    expect(pendingSandboxStopsForTests()).toEqual([])
  })
})

describe('the backstop (every RBAC sweep): every person with a running sandbox is checked again', () => {
  const running = (...people: Array<[string, 'own' | 'act_as']>) => ({
    mode: 'per_user', sandboxes: people.map(([user_id, view], i) => ({ user_id, view, instance: `a0000${i}`, state: 'running' })),
  })

  test('shared mode: nothing else is asked', async () => {
    h.list.mockResolvedValue({ mode: 'shared', sandboxes: [] })
    expect(await reconcileRunningSandboxes()).toEqual({ mode: 'shared' })
    for (const fn of [h.reconcile, h.stopSandbox, h.projectsFor, h.assertUser, h.principal]) expect(fn).not.toHaveBeenCalled()
  })

  test('an account that may still have one is reconciled once, both views (a policy change, an expired share or override)', async () => {
    h.list.mockResolvedValue(running(['bob', 'own'], ['bob', 'act_as'], ['carol', 'own']))
    h.reconcile.mockResolvedValueOnce(1).mockResolvedValueOnce(0)
    expect(await reconcileRunningSandboxes()).toEqual({ mode: 'per_user', stopped: 1 })
    expect(h.reconcile.mock.calls).toEqual([['bob', ['P-bob', 'P1'], ['P-bob']], ['carol', ['P-carol'], ['P-carol']]])
    expect(h.audit).toEqual([{
      ...SYSTEM_ACTOR, action: 'sandbox.stopped', targetType: 'user', targetId: 'bob', after: { reason: 'access_lost', stopped: 1 }, source: 'system',
    }])
    expect(h.requestActor).not.toHaveBeenCalled()
  })

  test('an account refused now is stopped with its reason: deleted (its folders go), disabled, stripped', async () => {
    h.list.mockResolvedValue(running(['gone', 'own'], ['off', 'own'], ['stripped', 'act_as']))
    h.assertUser.mockRejectedValue(new SandboxError(403, 'sandbox_user_refused'))
    h.principal.mockImplementation(async (id: string) => (id === 'gone' ? null : { id, status: id === 'off' ? 'disabled' : 'active' }))
    h.stopSandbox.mockResolvedValue(1)
    expect(await reconcileRunningSandboxes()).toEqual({ mode: 'per_user', stopped: 3 })
    expect(h.stopSandbox.mock.calls).toEqual([
      ['gone', 'account_deleted', null], ['off', 'account_disabled', null], ['stripped', 'access_lost', null],
    ])
    expect(h.reconcile).not.toHaveBeenCalled()
  })

  test("after a sharing-policy change it runs with Root's actor on every stop", async () => {
    h.list.mockResolvedValue(running(['bob', 'own'], ['gone', 'own']))
    h.assertUser.mockImplementation(async (id: string) => { if (id === 'gone') throw new SandboxError(403, 'sandbox_user_refused') })
    h.principal.mockImplementation(async (id: string) => (id === 'gone' ? null : { id, status: 'active' }))
    h.reconcile.mockResolvedValue(1)
    h.stopSandbox.mockResolvedValue(1)
    await reconcileRunningSandboxes(ADMIN)
    expect(h.audit[0]).toMatchObject({ ...ADMIN, targetId: 'bob' })
    expect(h.stopSandbox).toHaveBeenCalledWith('gone', 'account_deleted', ADMIN)
  })

  test('one failing goes on with the next; never throws; the log line carries counts only', async () => {
    h.list.mockResolvedValue(running(['bob', 'own'], ['carol', 'own']))
    h.reconcile.mockRejectedValueOnce(unreachable()).mockResolvedValueOnce(2)
    expect(await reconcileRunningSandboxes()).toEqual({ error: 'orchestrator_unreachable', stopped: 2 })
    const lines = warnLines().filter((l) => l.startsWith('[sandbox] backstop'))
    expect(lines).toEqual(['[sandbox] backstop people=2 stopped=2 failed=1'])
    h.list.mockRejectedValue(unreachable())
    expect(await reconcileRunningSandboxes()).toEqual({ error: 'orchestrator_unreachable', stopped: 0 })
  })

  test('bounded: at most BACKSTOP_MAX_PEOPLE people per sweep, and nobody more past the deadline', async () => {
    h.list.mockResolvedValue(running(...Array.from({ length: BACKSTOP_MAX_PEOPLE + 5 }, (_, i) => [`u${i}`, 'own'] as [string, 'own'])))
    await reconcileRunningSandboxes()
    expect(h.reconcile).toHaveBeenCalledTimes(BACKSTOP_MAX_PEOPLE)
    h.reconcile.mockReset().mockImplementation(() => new Promise(() => {}))
    vi.useFakeTimers()
    const pending = reconcileRunningSandboxes()
    await vi.advanceTimersByTimeAsync(LIFECYCLE_DEADLINE_MS + 1)
    expect(await pending).toEqual({ error: 'sandbox_timeout', stopped: 0 })
    expect(h.reconcile).toHaveBeenCalledTimes(1)
  })
})
