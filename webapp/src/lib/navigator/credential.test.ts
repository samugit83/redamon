/**
 * The navigator credential (plan §7.6): every refusal is the same, a resolved token names its live
 * run, and the token never reaches a log line.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests } from './runRegistry'
import { resolveCredentialValue } from './credential'
import { RUN_EXPIRY_S } from './constants'

let logs: string[] = []

beforeEach(() => {
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
  logs = []
  for (const level of ['log', 'warn', 'error', 'info', 'debug'] as const) {
    vi.spyOn(console, level).mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')) })
  }
})
afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
  setStopNotifierForTests(null)
})

function start(personId = 'alice') {
  const r = navigatorRuns().reserve({ personId, projectId: 'P1' })
  if (!r.ok) throw new Error()
  const token = navigatorRuns().complete(r.runId, {
    threadId: 'T1', tenantId: 'owner', actorId: null,
    login: { userId: personId, sessionVersion: 0, deviceSessionId: null, actAsStartId: null },
  })!
  return { runId: r.runId, token }
}

describe('resolve', () => {
  test('a live run resolves', () => {
    const { runId, token } = start()
    const got = resolveCredentialValue(token)
    expect('run' in got && got.run.runId).toBe(runId)
  })

  test.each([
    ['missing', null, 'missing'],
    ['empty', '', 'missing'],
    ['malformed', 'not a token!', 'malformed'],
    ['too short', 'abc', 'malformed'],
  ])('%s header refuses', (_n, value, code) => {
    expect(resolveCredentialValue(value as string | null)).toEqual({ refused: code })
  })

  test('an unknown token of the right shape refuses', () => {
    start()
    expect(resolveCredentialValue('A'.repeat(43))).toEqual({ refused: 'unknown' })
  })

  test('the token of an ended run refuses', () => {
    const { runId, token } = start()
    navigatorRuns().end(runId)
    expect(resolveCredentialValue(token)).toEqual({ refused: 'unknown' })
  })

  test('the token of an aborted run refuses', () => {
    const { token } = start()
    navigatorRuns().abortFor({ personId: 'alice' })
    expect(resolveCredentialValue(token)).toEqual({ refused: 'unknown' })
  })

  test('the token of an expired entry refuses', () => {
    vi.useFakeTimers()
    const { token } = start()
    vi.advanceTimersByTime((RUN_EXPIRY_S + 1) * 1000)
    expect(resolveCredentialValue(token)).toEqual({ refused: 'unknown' })
  })

  test('two runs get different tokens', () => {
    expect(start('alice').token).not.toBe(start('bob').token)
  })

  test('the token never appears in a log line', () => {
    const { token, runId } = start()
    navigatorRuns().end(runId)
    resolveCredentialValue(token)
    resolveCredentialValue(token.slice(0, 20))
    expect(logs.length).toBeGreaterThan(0)
    for (const line of logs) {
      expect(line).not.toContain(token)
      expect(line).not.toContain(token.slice(0, 20))
    }
  })
})
