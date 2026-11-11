/**
 * One password floor for every new password (HD-12): the admin create form, the
 * set and change modals, POST /api/users and the password route all ask this.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_BYTES,
  validateNewPassword,
  passwordPolicyMessage,
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
