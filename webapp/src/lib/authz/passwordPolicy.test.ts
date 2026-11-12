/**
 * One password floor for every new password (HD-12): the admin create form, the
 * set and change modals, POST /api/users and the password route all ask this.
 * Step 2.8 makes it one configurable policy (ID-20): the instance minimum, never below
 * the floor, and with the identity switch on a deny list and two rules.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_BYTES,
  validateNewPassword,
  passwordPolicyMessage,
  BASE_PASSWORD_POLICY,
  DENY_LIST,
  effectiveMinLength,
  describePasswordPolicy,
} from './passwordPolicy'

describe('validateNewPassword', () => {
  test('the floor is 12 characters and the ceiling 72 bytes', () => {
    expect(MIN_PASSWORD_LENGTH).toBe(12)
    expect(MAX_PASSWORD_BYTES).toBe(72)
  })

  test('11 characters refused', () => {
    expect(validateNewPassword('a'.repeat(11))).toEqual({
      ok: false, code: 'password_too_short', message: 'Password must be at least 12 characters',
    })
  })

  test('12 accepted', () => {
    expect(validateNewPassword('a'.repeat(12))).toEqual({ ok: true })
  })

  test('an empty password is too short (callers decide what empty means)', () => {
    expect(validateNewPassword('')).toMatchObject({ ok: false, code: 'password_too_short' })
  })

  test('72 bytes accepted', () => {
    expect(validateNewPassword('a'.repeat(72))).toEqual({ ok: true })
  })

  test('73 bytes refused', () => {
    expect(validateNewPassword('a'.repeat(73))).toMatchObject({ ok: false, code: 'password_too_long' })
  })

  test('multi-byte characters are counted in bytes for the ceiling', () => {
    // 'é' is 2 bytes in UTF-8: 36 of them are 72 bytes, 37 are 74.
    expect(validateNewPassword('é'.repeat(36))).toEqual({ ok: true })
    expect(validateNewPassword('é'.repeat(37))).toMatchObject({ ok: false, code: 'password_too_long' })
    // 19 four-byte emoji: 19 characters, 76 bytes.
    expect(validateNewPassword('🔑'.repeat(19))).toMatchObject({ ok: false, code: 'password_too_long' })
  })

  test('the floor counts characters, not UTF-16 units or bytes', () => {
    // 11 emoji are 22 UTF-16 units and 44 bytes, but 11 characters.
    expect(validateNewPassword('🔑'.repeat(11))).toMatchObject({ ok: false, code: 'password_too_short' })
    expect(validateNewPassword('🔑'.repeat(12))).toEqual({ ok: true })
  })

  test('the too-long message names the byte ceiling', () => {
    const r = validateNewPassword('a'.repeat(80))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.message).toBe(passwordPolicyMessage('password_too_long'))
    expect(passwordPolicyMessage('password_too_long')).toContain('72 bytes')
  })
})

describe('the configurable policy (step 2.8, ID-20, HD-12)', () => {
  const ON = { minLength: 12, rules: true }

  test('with no policy given it is the floor and the byte bound only (the switch off)', () => {
    expect(BASE_PASSWORD_POLICY).toEqual({ minLength: 12, rules: false })
    expect(validateNewPassword('password1234')).toEqual({ ok: true })
    expect(validateNewPassword('rbac-member@x.test', BASE_PASSWORD_POLICY, { email: 'rbac-member@x.test' })).toEqual({ ok: true })
  })

  test('policy reads the instance minimum', () => {
    const policy = { minLength: effectiveMinLength(16), rules: true }
    expect(validateNewPassword('a-b'.repeat(5), policy)).toEqual({
      ok: false, code: 'password_too_short', message: 'Password must be at least 16 characters',
    })
    expect(validateNewPassword('quiet-orchid-77', policy)).toMatchObject({ code: 'password_too_short' })
    expect(validateNewPassword('quiet-orchid-771', policy)).toEqual({ ok: true })
  })

  test.each([
    [8, 12], [11, 12], [0, 12], [-3, 12], [null, 12], [undefined, 12], ['16', 12], [12.5, 12], [NaN, 12],
    [12, 12], [16, 16], [72, 72], [90, 72],
  ])('never below 12: a stored minimum of %s reads as %s', (stored, expected) => {
    expect(effectiveMinLength(stored)).toBe(expected)
  })

  test('deny list', () => {
    expect(validateNewPassword('password1234', ON)).toEqual({
      ok: false, code: 'password_common', message: 'This password is too common: choose one that is not on the list of common passwords',
    })
    // Compared ignoring case.
    expect(validateNewPassword('PassWord1234', ON)).toMatchObject({ ok: false, code: 'password_common' })
    expect(validateNewPassword('Correct-orchid-paddle', ON)).toEqual({ ok: true })
  })

  test('the deny list is hand-written, lowercase, unique and holds only passwords the floor admits', () => {
    expect(DENY_LIST.length).toBeGreaterThanOrEqual(180)
    expect(DENY_LIST.length).toBeLessThanOrEqual(250)
    expect(new Set(DENY_LIST).size).toBe(DENY_LIST.length)
    for (const entry of DENY_LIST) {
      expect(entry, entry).toBe(entry.toLowerCase())
      expect([...entry].length, entry).toBeGreaterThanOrEqual(MIN_PASSWORD_LENGTH)
    }
  })

  test('email rule: not the email, not its local part, ignoring case', () => {
    const email = 'Rbac-Member-Long@e2e.local'
    expect(validateNewPassword('rbac-member-long@e2e.local', ON, { email })).toEqual({
      ok: false, code: 'password_is_email', message: 'The password must not be your email address or its name part',
    })
    expect(validateNewPassword('RBAC-MEMBER-LONG', ON, { email })).toMatchObject({ ok: false, code: 'password_is_email' })
    expect(validateNewPassword('rbac-member-long!', ON, { email })).toEqual({ ok: true })
    // Without an email the rule has nothing to compare.
    expect(validateNewPassword('rbac-member-long', ON)).toEqual({ ok: true })
  })

  test('one repeated character is refused', () => {
    expect(validateNewPassword('x'.repeat(14), ON)).toEqual({
      ok: false, code: 'password_repeated', message: 'The password must not be one character repeated',
    })
    expect(validateNewPassword('🔑'.repeat(12), ON)).toMatchObject({ ok: false, code: 'password_repeated' })
    expect(validateNewPassword('x'.repeat(13) + 'y', ON)).toEqual({ ok: true })
  })

  test('the length checks come first, so a short common password is told its length', () => {
    expect(validateNewPassword('password', ON)).toMatchObject({ code: 'password_too_short' })
    expect(validateNewPassword('a'.repeat(73), ON)).toMatchObject({ code: 'password_too_long' })
  })

  test('the text shown next to every password field states the policy, the 72-byte bound included', () => {
    expect(describePasswordPolicy(BASE_PASSWORD_POLICY))
      .toBe('At least 12 characters and at most 72 bytes.')
    expect(describePasswordPolicy({ minLength: 16, rules: true }))
      .toBe('At least 16 characters and at most 72 bytes; not a common password, not your email address or its name part, not one character repeated.')
  })
})
