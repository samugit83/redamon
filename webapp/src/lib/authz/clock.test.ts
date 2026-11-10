/**
 * The authorization core's clock (DV-12) is the plugin platform's clock.
 *
 * @vitest-environment node
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { now, setNowForTests } from './clock'
import * as pluginClock from '@/lib/plugins/clock'

afterEach(() => {
  vi.unstubAllEnvs()
  setNowForTests(null)
})

describe('authz clock', () => {
  test('now returns the injected time in tests', () => {
    let t = Date.parse('2026-03-01T10:00:00Z')
    setNowForTests(() => new Date(t))
    expect(now().toISOString()).toBe('2026-03-01T10:00:00.000Z')
    t += 15 * 60_000
    expect(now().toISOString()).toBe('2026-03-01T10:15:00.000Z')
  })

  test('the default is the real clock', () => {
    const before = Date.now()
    const t = now().getTime()
    expect(t).toBeGreaterThanOrEqual(before)
    expect(t).toBeLessThanOrEqual(Date.now())
  })

  test('the plugin clock and the authz clock are one clock', () => {
    expect(now).toBe(pluginClock.now)
    expect(setNowForTests).toBe(pluginClock.setNowForTests)

    setNowForTests(() => new Date('2026-05-05T05:05:05Z'))
    expect(pluginClock.now().toISOString()).toBe('2026-05-05T05:05:05.000Z')

    pluginClock.setNowForTests(() => new Date('2027-07-07T07:07:07Z'))
    expect(now().toISOString()).toBe('2027-07-07T07:07:07.000Z')
  })

  test('setNowForTests is refused in a production build', () => {
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => setNowForTests(() => new Date(0))).toThrow(/tests only/)
  })
})
