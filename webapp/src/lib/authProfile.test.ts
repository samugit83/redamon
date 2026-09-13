import { describe, test, expect } from 'vitest'
import {
  MAX_HEADER_VALUE_LEN,
  maskAuthValue,
  normalizeScopeHosts,
  parseAuthProfileInput,
  toAuthProfileMetadata,
} from './authProfile'

const ROW = {
  authType: 'cookie', authHeaderName: '', authValue: 'sid=secret-value',
  extraHeaders: { 'X-CSRF-Token': 'csrf-secret' }, scopeHosts: ['app.example.test'],
  source: 'manual', status: 'unknown', lastValidatedAt: null, updatedAt: null,
}

describe('toAuthProfileMetadata', () => {
  test('never carries a secret', () => {
    const meta = toAuthProfileMetadata(ROW)
    expect(JSON.stringify(meta)).not.toContain('secret')
    expect(meta).toMatchObject({ hasValue: true, extraHeaderNames: ['X-CSRF-Token'] })
    expect(meta).not.toHaveProperty('authValue')
    expect(meta).not.toHaveProperty('extraHeaders')
  })

  test('unknown future columns are not passed through', () => {
    const meta = toAuthProfileMetadata({ ...ROW, loginSequence: 'user=a&pass=b' } as typeof ROW)
    expect(meta).not.toHaveProperty('loginSequence')
  })

  test('null and empty profiles', () => {
    expect(toAuthProfileMetadata(null)).toBeNull()
    expect(toAuthProfileMetadata({ ...ROW, authValue: '', extraHeaders: {} })?.hasValue).toBe(false)
  })

  test('consumer gates default on, and pass through when set', () => {
    // Absent columns (older row) read as on.
    const m = toAuthProfileMetadata(ROW)
    expect(m).toMatchObject({ reconEnabled: true, agentEnabled: true })
    expect(toAuthProfileMetadata({ ...ROW, reconEnabled: false, agentEnabled: true }))
      .toMatchObject({ reconEnabled: false, agentEnabled: true })
  })
})

describe('parseAuthProfileInput', () => {
  test('absent authValue keeps the stored one (write-only form)', () => {
    const { patch, error } = parseAuthProfileInput({ authType: 'cookie', scopeHosts: ['a.test'] })
    expect(error).toBeNull()
    expect(patch).not.toHaveProperty('authValue')
    expect(parseAuthProfileInput({ authValue: '' }).patch).not.toHaveProperty('authValue')
  })

  test('clearValue is the only way to blank it', () => {
    expect(parseAuthProfileInput({ clearValue: true, authValue: 'x' }).patch.authValue).toBe('')
  })

  test('valid full write', () => {
    const { patch, error } = parseAuthProfileInput({
      authType: 'header', authHeaderName: ' X-Session ', authValue: ' tok ',
      extraHeaders: { 'X-CSRF-Token': 'c' }, scopeHosts: 'App.Example.test, *.api.example.test 10.0.0.0/24',
    })
    expect(error).toBeNull()
    expect(patch).toEqual({
      authType: 'header', authHeaderName: 'X-Session', authValue: 'tok',
      extraHeaders: { 'X-CSRF-Token': 'c' },
      scopeHosts: ['app.example.test', '*.api.example.test', '10.0.0.0/24'],
    })
  })

  test.each([
    [{ authType: 'kerberos' }, /authType/],
    [{ authValue: 'sid=a\r\nX-Injected: 1' }, /line breaks/],
    [{ authValue: 'sid=a\nb' }, /line breaks/],
    [{ authValue: 'sid=a;;X-Redamon-Ctx: x' }, /;;/],
    [{ authValue: 'a'.repeat(MAX_HEADER_VALUE_LEN + 1) }, /longer/],
    [{ authValue: 42 }, /string/],
    [{ authHeaderName: 'Bad Name' }, /Invalid header name/],
    [{ authHeaderName: 'X-Redamon-Ctx' }, /reserved/],
    [{ extraHeaders: { 'x-redamon-ctx': 'v' } }, /reserved/],
    [{ extraHeaders: { 'X-A': 'v\r\n' } }, /line breaks/],
    [{ extraHeaders: ['X-A: v'] }, /object/],
    [{ scopeHosts: ['https://app.example.test/path'] }, /Invalid scope host/],
    [{ scopeHosts: [42] }, /strings/],
  ])('rejects %j', (input, message) => {
    expect(parseAuthProfileInput(input as Record<string, unknown>).error).toMatch(message)
  })

  test('tab is allowed in a value', () => {
    expect(parseAuthProfileInput({ authValue: 'a\tb' }).error).toBeNull()
  })

  test('accepts boolean consumer gates, rejects non-boolean', () => {
    expect(parseAuthProfileInput({ reconEnabled: false, agentEnabled: true }).patch)
      .toEqual({ reconEnabled: false, agentEnabled: true })
    expect(parseAuthProfileInput({ reconEnabled: 'yes' as unknown as boolean }).error).toMatch(/boolean/)
  })
})

describe('normalizeScopeHosts', () => {
  test('dedupes, lowercases, drops trailing dot and blanks', () => {
    expect(normalizeScopeHosts(['A.test.', 'a.test', ' ', '::1']).hosts).toEqual(['a.test', '::1'])
  })
})

test('maskAuthValue mirrors recon mask_auth_value', () => {
  expect(maskAuthValue('')).toBe('')
  expect(maskAuthValue('abc')).toBe('***')
  expect(maskAuthValue('abcde')).toBe('ab***')
  expect(maskAuthValue('abcdefghijklmnop')).toBe('abcd...mnop')
})
