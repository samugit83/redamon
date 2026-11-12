/**
 * The invite routes' own limiter (step 2.9, DV-05, ID-15). `loginThrottle` keys on the address
 * only when the client IP is trusted, so on a local install it limits nobody by address; the
 * invite routes therefore keep, per copy and whatever the IP trust:
 *   - a ceiling of 30 link lookups a minute (each one is a database read an anonymous caller
 *     can cause);
 *   - five failed accepts per link, after which the route cancels the link.
 * Time comes from the injected clock.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { setNowForTests } from './clock'
import {
  FAILED_ACCEPT_LIMIT,
  LOOKUPS_PER_MINUTE,
  forgetFailedAccepts,
  recordFailedAccept,
  resetInviteLimitsForTests,
  takeLookup,
} from './inviteLimits'

const T0 = new Date('2026-11-12T10:00:00Z').getTime()
let clock = T0

beforeEach(() => {
  resetInviteLimitsForTests()
  clock = T0
  setNowForTests(() => new Date(clock))
})
afterEach(() => setNowForTests(null))

describe('the lookup ceiling', () => {
  test('rate limit after N without a trusted IP: the 31st lookup in a minute is refused', () => {
    expect(LOOKUPS_PER_MINUTE).toBe(30)
    for (let i = 0; i < 30; i++) {
      clock = T0 + i * 1000
      expect(takeLookup(), `lookup ${i + 1}`).toEqual({ ok: true })
    }
    clock = T0 + 30_000
    expect(takeLookup()).toEqual({ ok: false, retryAfterSeconds: 30 })
  })

  test('the window slides: a lookup is allowed again once the oldest is a minute old', () => {
    for (let i = 0; i < 30; i++) {
      clock = T0 + i * 1000
      takeLookup()
    }
    clock = T0 + 59_999
    expect(takeLookup().ok).toBe(false)
    clock = T0 + 60_000
    expect(takeLookup()).toEqual({ ok: true })
    expect(takeLookup().ok).toBe(false)
  })

  test('a refused lookup does not extend the wait', () => {
    for (let i = 0; i < 30; i++) takeLookup()
    for (let i = 0; i < 100; i++) takeLookup()
    clock = T0 + 60_000
    expect(takeLookup()).toEqual({ ok: true })
  })
})

describe('failed accepts per link', () => {
  test('counted per link, five is the limit', () => {
    expect(FAILED_ACCEPT_LIMIT).toBe(5)
    expect([1, 2, 3, 4, 5].map(() => recordFailedAccept('hash-a'))).toEqual([1, 2, 3, 4, 5])
    expect(recordFailedAccept('hash-b')).toBe(1)
  })

  test('forgotten once the link is used or locked', () => {
    recordFailedAccept('hash-a')
    recordFailedAccept('hash-a')
    forgetFailedAccepts('hash-a')
    expect(recordFailedAccept('hash-a')).toBe(1)
  })

  test('the counts are bounded: a flood of links cannot grow the map without end', () => {
    for (let i = 0; i < 20_000; i++) recordFailedAccept(`hash-${i}`)
    expect(recordFailedAccept('hash-19999')).toBe(2)
    expect(recordFailedAccept('hash-0')).toBe(1)
  })
})
