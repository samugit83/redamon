/**
 * AI Navigator run registry (plan §7.5): the synchronous reservation, the abort selectors, the
 * expiry, and one store across module copies.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests, type RunLogin } from './runRegistry'
import { RUN_EXPIRY_S } from './constants'

const login = (over: Partial<RunLogin> = {}): RunLogin => ({
  userId: 'alice', sessionVersion: 0, deviceSessionId: null, actAsStartId: null, ...over,
})
const stops: string[] = []

beforeEach(() => {
  clearNavigatorRunsForTests()
  stops.length = 0
  setStopNotifierForTests((id) => stops.push(id))
})
afterEach(() => {
  setStopNotifierForTests(null)
  vi.useRealTimers()
})

function live(personId: string, projectId: string, over: Partial<{ actorId: string | null; login: RunLogin; threadId: string }> = {}) {
  const r = navigatorRuns().reserve({ personId, projectId })
  if (!r.ok) throw new Error('reserve refused')
  const token = navigatorRuns().complete(r.runId, {
    threadId: over.threadId ?? `T-${r.runId}`, tenantId: 'owner', actorId: over.actorId ?? null, login: over.login ?? login({ userId: personId }),
  })
  return { runId: r.runId, token: token! }
}

describe('reserve', () => {
  test('two concurrent reservations for one (person, project): exactly one passes', async () => {
    const [a, b] = await Promise.all([
      Promise.resolve().then(() => navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' })),
      Promise.resolve().then(() => navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' })),
    ])
    expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1)
    expect([a, b].find((x) => !x.ok)).toEqual({ ok: false, code: 'busy' })
  })

  test('at most two runs per person across projects', () => {
    expect(navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' }).ok).toBe(true)
    expect(navigatorRuns().reserve({ personId: 'alice', projectId: 'P2' }).ok).toBe(true)
    expect(navigatorRuns().reserve({ personId: 'alice', projectId: 'P3' })).toEqual({ ok: false, code: 'busy' })
    expect(navigatorRuns().reserve({ personId: 'bob', projectId: 'P1' }).ok).toBe(true)
  })

  test('a released reservation frees its slot', () => {
    const r = navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' })
    if (!r.ok) throw new Error()
    navigatorRuns().release(r.runId)
    expect(navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' }).ok).toBe(true)
  })

  test('an expired entry frees its slot and its credential stops resolving', () => {
    vi.useFakeTimers()
    const { token } = live('alice', 'P1')
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    vi.advanceTimersByTime((RUN_EXPIRY_S + 1) * 1000)
    expect(navigatorRuns().countFor('alice')).toBe(0)
    expect(navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' }).ok).toBe(true)
  })

  test('complete answers a different token per run', () => {
    expect(live('alice', 'P1').token).not.toBe(live('bob', 'P1').token)
  })
})

describe('abort selectors hit only their runs', () => {
  test('abortFor a person, optionally on some projects', () => {
    live('alice', 'P1'); live('alice', 'P2'); live('bob', 'P1')
    expect(navigatorRuns().abortFor({ personId: 'alice', projectIds: ['P2'] })).toBe(1)
    expect(navigatorRuns().countFor('alice')).toBe(1)
    expect(navigatorRuns().abortFor({ personId: 'alice' })).toBe(1)
    expect(navigatorRuns().countFor('bob')).toBe(1)
  })

  test('abortProject', () => {
    live('alice', 'P1'); live('bob', 'P1'); live('carol', 'P2')
    expect(navigatorRuns().abortProject('P1')).toBe(2)
    expect(navigatorRuns().countAll()).toBe(1)
  })

  test('abortDeviceSession', () => {
    live('alice', 'P1', { login: login({ deviceSessionId: 'sid-1' }) })
    live('alice', 'P2', { login: login({ deviceSessionId: 'sid-2' }) })
    expect(navigatorRuns().abortDeviceSession('sid-1')).toBe(1)
    expect(navigatorRuns().countFor('alice')).toBe(1)
  })

  test('abortActAs by start, or every run of that admin and person without one', () => {
    live('alice', 'P1', { actorId: 'admin', login: login({ userId: 'admin', actAsStartId: 'start-1' }) })
    live('alice', 'P2', { actorId: 'admin', login: login({ userId: 'admin', actAsStartId: 'start-2' }) })
    live('bob', 'P1', { actorId: 'admin', login: login({ userId: 'admin', actAsStartId: 'start-3' }) })
    expect(navigatorRuns().abortActAs({ startId: 'start-1', adminId: 'admin', targetUserId: 'alice' })).toBe(1)
    expect(navigatorRuns().abortActAs({ startId: null, adminId: 'admin', targetUserId: 'alice' })).toBe(1)
    expect(navigatorRuns().countFor('bob')).toBe(1)
  })

  test('abortActor and abortAll', () => {
    live('alice', 'P1', { actorId: 'admin' }); live('bob', 'P1')
    expect(navigatorRuns().abortActor('admin')).toBe(1)
    expect(navigatorRuns().abortAll()).toBe(1)
    expect(navigatorRuns().countAll()).toBe(0)
  })

  test('an abort fires the controller and tells the agent', () => {
    const { runId } = live('alice', 'P1')
    const run = navigatorRuns().get(runId)!
    navigatorRuns().abortThread(run.threadId!)
    expect(run.abort.signal.aborted).toBe(true)
    expect(stops).toEqual([runId])
  })

  test('aborting a bare reservation tells the agent nothing (it never started)', () => {
    navigatorRuns().reserve({ personId: 'alice', projectId: 'P1' })
    expect(navigatorRuns().abortAll()).toBe(1)
    expect(stops).toEqual([])
  })

  test('a reservation is bound to its login: a device revoke or the act-as end before complete() ends it', () => {
    // The messages route awaits the database between reserve() and complete(); a revoke landing
    // there used to match nothing, and the run started anyway.
    const lg = login({ userId: 'admin', deviceSessionId: 'sid-1', actAsStartId: 'start-1' })
    const reserveAs = () => {
      const r = navigatorRuns().reserve({ personId: 'alice', projectId: 'P1', actorId: 'admin', login: lg })
      if (!r.ok) throw new Error('reserve refused')
      return r.runId
    }
    const completes = (runId: string) =>
      navigatorRuns().complete(runId, { threadId: 'T1', tenantId: 'owner', actorId: 'admin', login: lg })

    let runId = reserveAs()
    expect(navigatorRuns().abortDeviceSession('sid-1')).toBe(1)
    expect(completes(runId)).toBeNull()
    runId = reserveAs()
    expect(navigatorRuns().abortActAs({ startId: 'start-1', adminId: 'admin', targetUserId: 'alice' })).toBe(1)
    expect(completes(runId)).toBeNull()
    runId = reserveAs()
    expect(navigatorRuns().abortActor('admin')).toBe(1)
    expect(completes(runId)).toBeNull()
    expect(stops).toEqual([])
  })
})

test('the store is shared across two module instances', async () => {
  live('alice', 'P1')
  vi.resetModules()
  const fresh = await import('./runRegistry')
  expect(fresh.navigatorRuns().countFor('alice')).toBe(1)
})
