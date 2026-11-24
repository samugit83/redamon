/**
 * S11 — login throttle: lockout after N failures, clears on success, expires,
 * per-account and per-IP keys, bounded map.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/loginThrottle.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest'
import {
  checkLockout, recordFailure, clearAttempts, checkDeviceLockout, recordDeviceFailure, clearDeviceAttempts, __resetThrottle,
} from './loginThrottle'

beforeEach(() => {
  __resetThrottle()
  vi.stubEnv('LOGIN_MAX_ATTEMPTS', '3')
  vi.stubEnv('LOGIN_LOCKOUT_SECONDS', '60')
})
afterEach(() => vi.unstubAllEnvs())

describe('login throttle', () => {
  test('locks after N failures (per account)', () => {
    for (let i = 0; i < 2; i++) recordFailure('user@x.com', '1.1.1.1')
    expect(checkLockout('user@x.com', '1.1.1.1').locked).toBe(false)
    recordFailure('user@x.com', '1.1.1.1') // 3rd -> lock
    const s = checkLockout('user@x.com', '1.1.1.1')
    expect(s.locked).toBe(true)
    expect(s.retryAfterSeconds).toBeGreaterThan(0)
  })

  test('clears on success', () => {
    for (let i = 0; i < 3; i++) recordFailure('u@x.com', '2.2.2.2')
    expect(checkLockout('u@x.com', '2.2.2.2').locked).toBe(true)
    clearAttempts('u@x.com', '2.2.2.2')
    expect(checkLockout('u@x.com', '2.2.2.2').locked).toBe(false)
  })

  test('lockout expires after the window', () => {
    const t0 = 1_000_000
    for (let i = 0; i < 3; i++) recordFailure('e@x.com', '3.3.3.3', t0)
    expect(checkLockout('e@x.com', '3.3.3.3', t0).locked).toBe(true)
    // 61s later the 60s lockout has elapsed.
    expect(checkLockout('e@x.com', '3.3.3.3', t0 + 61_000).locked).toBe(false)
  })

  test('per-IP key locks even across different emails', () => {
    // Same IP, different emails, 3 total failures -> IP key trips.
    recordFailure('a@x.com', '9.9.9.9')
    recordFailure('b@x.com', '9.9.9.9')
    recordFailure('c@x.com', '9.9.9.9')
    // A fresh email from the SAME ip is now locked by the ip key.
    expect(checkLockout('d@x.com', '9.9.9.9').locked).toBe(true)
  })

  test('another account/ip is unaffected', () => {
    for (let i = 0; i < 3; i++) recordFailure('locked@x.com', '4.4.4.4')
    expect(checkLockout('free@x.com', '5.5.5.5').locked).toBe(false)
  })
})

// D6: a known device is counted on its own key, apart from the e-mail and IP keys.
describe('known-device keys', () => {
  test('a locked e-mail does not lock a known device', () => {
    for (let i = 0; i < 3; i++) recordFailure('root@x.com', null)
    expect(checkLockout('root@x.com', null).locked).toBe(true)
    expect(checkDeviceLockout('dev-1').locked).toBe(false)
  })

  test('a device locks after N failures of its own, and only itself', () => {
    for (let i = 0; i < 2; i++) recordDeviceFailure('dev-1')
    expect(checkDeviceLockout('dev-1').locked).toBe(false)
    expect(recordDeviceFailure('dev-1').locked).toBe(true)
    expect(checkDeviceLockout('dev-1').locked).toBe(true)
    expect(checkDeviceLockout('dev-2').locked).toBe(false)
    expect(checkLockout('root@x.com', null).locked).toBe(false)
  })

  test('a device success clears the device, never the e-mail', () => {
    for (let i = 0; i < 3; i++) recordFailure('root@x.com', null)
    for (let i = 0; i < 3; i++) recordDeviceFailure('dev-1')
    clearDeviceAttempts('dev-1')
    expect(checkDeviceLockout('dev-1').locked).toBe(false)
    expect(checkLockout('root@x.com', null).locked).toBe(true)
  })

  test('an e-mail that reads like a device key stays an e-mail key', () => {
    for (let i = 0; i < 3; i++) recordFailure('device:dev-1', null)
    expect(checkDeviceLockout('dev-1').locked).toBe(false)
  })

  test('a device lockout expires like any other', () => {
    const t0 = 2_000_000
    for (let i = 0; i < 3; i++) recordDeviceFailure('dev-1', t0)
    expect(checkDeviceLockout('dev-1', t0).locked).toBe(true)
    expect(checkDeviceLockout('dev-1', t0 + 61_000).locked).toBe(false)
  })
})
