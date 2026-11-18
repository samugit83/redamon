/**
 * What a browser sees of a resource's secrets (U1, §6.6).
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { isMaskedValue, maskCredentials, maskResource, maskSecret, secretState } from './masking'

describe('masking', () => {
  test('the 1.x token format: the last four characters only', () => {
    expect(maskSecret('ghp_SECRETVALUE9876')).toBe('••••••••9876')
    expect(maskSecret('abc')).toBe('••••')
    expect(maskSecret('')).toBe('')
  })

  test('maskResource masks the token and the login and keeps every other column', () => {
    const masked = maskResource({
      id: 'r1', name: 'Wiki', githubTokenOverride: 'ghp_SECRETVALUE9876',
      credentials: { cookie: 'session=fake-session', headers: [{ name: 'X-Api-Key', value: 'fake-key-123' }], basic_auth: { username: 'bob', password: 'fake-pass' } },
    })
    expect(masked).toEqual({
      id: 'r1', name: 'Wiki', githubTokenOverride: '••••••••9876',
      credentials: { cookie: 'set', headers: [{ name: 'X-Api-Key', value: 'set' }], basic_auth: { username: 'bob', password: 'set' } },
    })
    const text = JSON.stringify(masked)
    for (const secret of ['SECRETVALUE', 'fake-session', 'fake-key-123', 'fake-pass']) expect(text).not.toContain(secret)
  })

  test('a 1.x row (no login column) gains none', () => {
    expect(maskResource({ id: 'r1', githubTokenOverride: '' })).toEqual({ id: 'r1', githubTokenOverride: '' })
  })

  test('an empty or malformed login masks to nothing set', () => {
    expect(maskCredentials({})).toEqual({ cookie: '', headers: [], basic_auth: null })
    expect(maskCredentials('junk')).toEqual({ cookie: '', headers: [], basic_auth: null })
    expect(maskCredentials({ headers: [null, { name: 'A', value: '' }] })).toEqual({ cookie: '', headers: [{ name: 'A', value: '' }], basic_auth: null })
  })

  test('secretState and the values that mean "keep it"', () => {
    expect(secretState('x')).toBe('set')
    expect(secretState('')).toBe('')
    expect(secretState(undefined)).toBe('')
    expect(isMaskedValue('••••••••9876')).toBe(true)
    expect(isMaskedValue('set')).toBe(true)
    expect(isMaskedValue('ghp_new')).toBe(false)
  })
})
