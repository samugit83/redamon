/**
 * The owner check of a per-user row (step 3.6): a preset, a mute-rule preset, a conversation or a
 * user-scope override set names its owner's id, and only that account (the effective user,
 * under act-as the account acted as) may use it. Strict: nothing but an exact, non-empty match.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { ownsRow, rowOwnerFilter } from './rowOwner'

describe('ownsRow', () => {
  test('the owner owns the row', () => {
    expect(ownsRow({ userId: 'u1' }, 'u1')).toBe(true)
  })

  test("another account's row is not owned", () => {
    expect(ownsRow({ userId: 'u1' }, 'u2')).toBe(false)
    expect(ownsRow({ userId: 'u1' }, 'U1')).toBe(false)
    expect(ownsRow({ userId: 'u1' }, ' u1')).toBe(false)
  })

  test('an empty id on either side owns nothing (fail closed)', () => {
    expect(ownsRow({ userId: '' }, '')).toBe(false)
    expect(ownsRow({ userId: '' }, 'u1')).toBe(false)
    expect(ownsRow({ userId: 'u1' }, '')).toBe(false)
  })

  test('a row without an owner id owns nothing', () => {
    expect(ownsRow({ userId: 'u1' }, null)).toBe(false)
    expect(ownsRow({ userId: 'u1' }, undefined)).toBe(false)
    expect(ownsRow({ userId: 'u1' }, 42)).toBe(false)
  })
})

describe('rowOwnerFilter', () => {
  test("scopes a list query to the account's own rows", () => {
    expect(rowOwnerFilter({ userId: 'u9' })).toEqual({ userId: 'u9' })
  })

  test('carries nothing but the user id', () => {
    const subject = { userId: 'u9', role: 'admin', realUserId: 'a1' } as { userId: string }
    expect(rowOwnerFilter(subject)).toEqual({ userId: 'u9' })
  })
})
