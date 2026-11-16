/**
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { validateFocus } from './focusFields'

describe('validateFocus (stub until T5.5)', () => {
  test('nothing or an empty focus', () => {
    expect(validateFocus(undefined)).toEqual({ ok: true, value: {} })
    expect(validateFocus({})).toEqual({ ok: true, value: {} })
  })
  test.each([[{ mode: 'focused' }], [[]], ['x'], [null]])('anything else is refused: %j', (input) => {
    expect(validateFocus(input).ok).toBe(false)
  })
})
